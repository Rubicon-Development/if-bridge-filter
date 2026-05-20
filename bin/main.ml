let usage () =
  Printf.eprintf
    "Usage:\n  %s attach --ifaces eth0,eth1 --src 192.168.1.10 --dst 192.168.2.20\n  \
%s detach --ifaces eth0,eth1\n  %s counters\n"
    Sys.argv.(0)
    Sys.argv.(0)
    Sys.argv.(0)
;
  exit 1
;;

let parse_ifaces s =
  String.split_on_char ',' s |> List.filter (fun x -> String.length x > 0)
;;

let parse_v4 name s =
  match Ipaddr.V4.of_string s with
  | Ok ip -> ip
  | Error (`Msg m) -> failwith (Printf.sprintf "Invalid %s IP: %s (%s)" name s m)
;;

let () =
  try
    if Array.length Sys.argv < 2 then usage ();
    match Sys.argv.(1) with
    | "attach" ->
      if Array.length Sys.argv <> 8 then usage ();
      if Sys.argv.(2) <> "--ifaces" || Sys.argv.(4) <> "--src" || Sys.argv.(6) <> "--dst"
      then usage ();
      let interfaces = parse_ifaces Sys.argv.(3) in
      let src_ip = parse_v4 "source" Sys.argv.(5) in
      let dst_ip = parse_v4 "destination" Sys.argv.(7) in
      If_bridge_filter.Tc_loader.attach
        ~interfaces
        ~policy:{ If_bridge_filter.Tc_loader.src_ip; dst_ip };
      Printf.printf
        "Attached modbus filter on [%s] for %s -> %s\n"
        (String.concat "," interfaces)
        (Ipaddr.V4.to_string src_ip)
        (Ipaddr.V4.to_string dst_ip)
    | "detach" ->
      if Array.length Sys.argv <> 4 || Sys.argv.(2) <> "--ifaces" then usage ();
      let interfaces = parse_ifaces Sys.argv.(3) in
      If_bridge_filter.Tc_loader.detach ~interfaces;
      Printf.printf "Detached modbus filter from [%s]\n" (String.concat "," interfaces)
    | "counters" -> If_bridge_filter.Tc_loader.show_counters ()
    | _ -> usage ()
  with
  | Failure msg ->
    prerr_endline msg;
    exit 2
;;
