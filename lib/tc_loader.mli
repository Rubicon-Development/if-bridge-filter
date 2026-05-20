type policy = {
  src_ip : Ipaddr.V4.t;
  dst_ip : Ipaddr.V4.t;
}

val attach : interfaces:string list -> policy:policy -> unit
val detach : interfaces:string list -> unit
val show_counters : unit -> unit
