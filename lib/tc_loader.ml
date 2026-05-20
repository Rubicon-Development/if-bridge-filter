open Ctypes
open Libbpf

type policy = {
  src_ip : Ipaddr.V4.t;
  dst_ip : Ipaddr.V4.t;
}

let object_candidates () =
  [ Filename.concat (Filename.dirname Sys.executable_name) "modbus_filter.bpf.o"
  ; "modbus_filter.bpf.o"
  ; "lib/modbus_filter.bpf.o"
  ]
;;

let find_bpf_object () =
  match List.find_opt Sys.file_exists (object_candidates ()) with
  | Some p -> p
  | None -> failwith "Cannot find modbus_filter.bpf.o"
;;

let get_ifindex ifname =
  let if_nametoindex = Foreign.foreign "if_nametoindex" (string @-> returning uint) in
  let idx = if_nametoindex ifname |> Unsigned.UInt.to_int in
  if idx = 0 then failwith ("Interface not found: " ^ ifname) else idx
;;

let ipv4_to_u32 ip =
  let s = Ipaddr.V4.to_octets ip in
  Unsigned.UInt32.logor
    (Unsigned.UInt32.shift_left (Unsigned.UInt32.of_int (Char.code s.[0])) 24)
    (Unsigned.UInt32.logor
       (Unsigned.UInt32.shift_left (Unsigned.UInt32.of_int (Char.code s.[1])) 16)
       (Unsigned.UInt32.logor
          (Unsigned.UInt32.shift_left (Unsigned.UInt32.of_int (Char.code s.[2])) 8)
          (Unsigned.UInt32.of_int (Char.code s.[3]))))
;;

let setup_tc interface =
  let ifindex = get_ifindex interface in
  let tc_hook = make C.Types.Bpf_tc.hook in
  setf tc_hook C.Types.Bpf_tc.ifindex ifindex;
  setf tc_hook C.Types.Bpf_tc.attach_point `INGRESS;
  setf tc_hook C.Types.Bpf_tc.sz (Unsigned.Size_t.of_int (sizeof C.Types.Bpf_tc.hook));
  let tc_opts = make C.Types.Bpf_tc.Opts.t in
  setf tc_opts C.Types.Bpf_tc.Opts.handle (Unsigned.UInt32.of_int 1);
  setf tc_opts C.Types.Bpf_tc.Opts.priority (Unsigned.UInt32.of_int 1);
  setf tc_opts C.Types.Bpf_tc.Opts.sz (Unsigned.Size_t.of_int (sizeof C.Types.Bpf_tc.Opts.t));
  tc_hook, tc_opts
;;

let attach_one ~obj ~interface =
  let tc_hook, tc_opts = setup_tc interface in
  let ensure_clsact () =
    let cmd = Printf.sprintf "tc qdisc replace dev %s clsact >/dev/null 2>&1" interface in
    ignore (Sys.command cmd)
  in
  ensure_clsact ();
  ignore (C.Functions.bpf_tc_hook_destroy (addr tc_hook));
  let created = C.Functions.bpf_tc_hook_create (addr tc_hook) = 0 in
  let prog = bpf_object_find_program_by_name obj "modbus_filter_ingress" in
  setf tc_opts C.Types.Bpf_tc.Opts.prog_fd prog.fd;
  setf tc_opts C.Types.Bpf_tc.Opts.flags (Unsigned.UInt32.of_int 1);
  let err = C.Functions.bpf_tc_attach (addr tc_hook) (addr tc_opts) in
  if err <> 0
  then (
    if created then ignore (C.Functions.bpf_tc_hook_destroy (addr tc_hook));
    failwith (Printf.sprintf "Failed to attach on %s: %d" interface err))
;;

let detach_one interface =
  let tc_hook, tc_opts = setup_tc interface in
  ignore (C.Functions.bpf_tc_detach (addr tc_hook) (addr tc_opts));
  ignore (C.Functions.bpf_tc_hook_destroy (addr tc_hook))
;;

let set_policy obj { src_ip; dst_ip } =
  let map = bpf_object_find_map_by_name obj "policy_map" in
  let key = Unsigned.UInt32.zero in
  let key_ty = uint32_t in
  let value_ty = structure "flow_policy" in
  let src = field value_ty "src_ip" uint32_t in
  let dst = field value_ty "dst_ip" uint32_t in
  let () = seal value_ty in
  let v = make value_ty in
  setf v src (ipv4_to_u32 src_ip);
  setf v dst (ipv4_to_u32 dst_ip);
  bpf_map_update_elem ~key_ty ~val_ty:value_ty map key v
;;

let attach ~interfaces ~policy =
  let obj = bpf_object_open (find_bpf_object ()) in
  Fun.protect
    ~finally:(fun () -> bpf_object_close obj)
    (fun () ->
      bpf_object_load obj;
      set_policy obj policy;
      List.iter (fun iface -> attach_one ~obj ~interface:iface) interfaces)
;;

let detach ~interfaces = List.iter detach_one interfaces

let show_counters () =
  let cmd =
    "bpftool map show | sed -n '/name counters/{s/.*id \\([0-9][0-9]*\\).*/\\1/p; q}'"
  in
  let ic = Unix.open_process_in cmd in
  let map_id =
    try input_line ic with
    | End_of_file -> ""
  in
  ignore (Unix.close_process_in ic);
  if map_id = ""
  then print_endline "No map named 'counters' found. Is filter attached?"
  else ignore (Sys.command ("bpftool map dump id " ^ map_id))
;;
