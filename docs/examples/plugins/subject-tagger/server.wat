;; Subject tagger: a server plug-in written directly in WebAssembly text, so it needs no
;; build step. It shows the whole ABI: `alloc`, `handle`, and a request to the host
;; (`call` returns the reply's length; `reply` copies it into memory the module allocated).
;;
;; For incoming mail it adds `X-Tagged-By: subject-tagger` and puts the administrator's prefix
;; (the `prefix` setting) in front of the subject, unless it is there already. For requests to
;; its route (/api/x/subject-tagger/...) it answers with the prefix in use.
;;
;; Kept deliberately small: it finds values by scanning the JSON text, which is enough for
;; the fixed shapes the server sends. Real plug-ins are easier to write in a language that
;; compiles to WebAssembly (Rust, Go, AssemblyScript, Zig) with a JSON library.
(module
  (import "unomail" "call" (func $host (param i32 i32) (result i32)))
  (import "unomail" "reply" (func $reply (param i32)))
  (memory (export "memory") 2)
  ;; Constant texts live below 1024; everything allocated comes after 64 KiB.
  (data (i32.const 0) "\"event\":\"http:request\"")
  (data (i32.const 32) "\"prefix\":\"")
  (data (i32.const 48) "[\"Subject\",\"")
  (data (i32.const 64) "{\"op\":\"settings.admin\"}")
  (data (i32.const 96) "{\"action\":\"accept\",\"addHeaders\":[[\"X-Tagged-By\",\"subject-tagger\"]]")
  (data (i32.const 176) ",\"setHeaders\":[[\"Subject\",\"")
  (data (i32.const 208) "\"]]")
  (data (i32.const 224) "}")
  (data (i32.const 240) "{\"status\":200,\"json\":{\"prefix\":\"")
  (data (i32.const 272) "\"}}")
  (data (i32.const 288) " ")
  (global $heap (mut i32) (i32.const 65536))
  (global $out (mut i32) (i32.const 0))

  ;; A bump allocator: each call gets a fresh instance, so nothing is ever freed.
  (func $alloc (export "alloc") (param $len i32) (result i32)
    (local $ptr i32) (local $pages i32)
    (local.set $ptr (global.get $heap))
    (global.set $heap (i32.and (i32.add (i32.add (global.get $heap) (local.get $len)) (i32.const 7)) (i32.const -8)))
    (local.set $pages (i32.shr_u (i32.add (global.get $heap) (i32.const 65535)) (i32.const 16)))
    (if (i32.gt_u (local.get $pages) (memory.size))
      (then (if (i32.eq (memory.grow (i32.sub (local.get $pages) (memory.size))) (i32.const -1)) (then (unreachable)))))
    (local.get $ptr))

  ;; Where `needle` first occurs in `hay`, as an address, or -1.
  (func $find (param $h i32) (param $hl i32) (param $n i32) (param $nl i32) (result i32)
    (local $i i32) (local $j i32)
    (block $missing
      (loop $outer
        (br_if $missing (i32.gt_u (i32.add (local.get $i) (local.get $nl)) (local.get $hl)))
        (local.set $j (i32.const 0))
        (block $mismatch
          (loop $inner
            (if (i32.eq (local.get $j) (local.get $nl)) (then (return (i32.add (local.get $h) (local.get $i)))))
            (br_if $mismatch (i32.ne
              (i32.load8_u (i32.add (i32.add (local.get $h) (local.get $i)) (local.get $j)))
              (i32.load8_u (i32.add (local.get $n) (local.get $j)))))
            (local.set $j (i32.add (local.get $j) (i32.const 1)))
            (br $inner)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $outer)))
    (i32.const -1))

  ;; The closing quote of a JSON string starting at `p` (escapes skipped), or `end`.
  (func $string_end (param $p i32) (param $end i32) (result i32)
    (local $c i32)
    (block $done
      (loop $next
        (br_if $done (i32.ge_u (local.get $p) (local.get $end)))
        (local.set $c (i32.load8_u (local.get $p)))
        (if (i32.eq (local.get $c) (i32.const 34)) (then (return (local.get $p))))
        (local.set $p (i32.add (local.get $p) (select (i32.const 2) (i32.const 1) (i32.eq (local.get $c) (i32.const 92)))))
        (br $next)))
    (local.get $end))

  (func $emit (param $src i32) (param $len i32)
    (memory.copy (global.get $out) (local.get $src) (local.get $len))
    (global.set $out (i32.add (global.get $out) (local.get $len))))

  (func (export "handle") (param $ptr i32) (param $len i32) (result i64)
    (local $end i32) (local $start i32) (local $rptr i32) (local $rlen i32)
    (local $p i32) (local $pstart i32) (local $pend i32) (local $s i32) (local $sstart i32) (local $send i32)
    (local.set $end (i32.add (local.get $ptr) (local.get $len)))

    ;; The prefix, from the administrator's settings (its default comes from the manifest).
    (local.set $rlen (call $host (i32.const 64) (i32.const 23)))
    (local.set $rptr (call $alloc (local.get $rlen)))
    (call $reply (local.get $rptr))
    (local.set $p (call $find (local.get $rptr) (local.get $rlen) (i32.const 32) (i32.const 10)))
    (if (i32.ne (local.get $p) (i32.const -1))
      (then
        (local.set $pstart (i32.add (local.get $p) (i32.const 10)))
        (local.set $pend (call $string_end (local.get $pstart) (i32.add (local.get $rptr) (local.get $rlen))))))

    ;; Room for the answer: the event's size is always enough for what is copied from it.
    (local.set $start (call $alloc (i32.add (local.get $len) (i32.const 4096))))
    (global.set $out (local.get $start))

    (if (i32.ne (call $find (local.get $ptr) (local.get $len) (i32.const 0) (i32.const 22)) (i32.const -1))
      (then
        (call $emit (i32.const 240) (i32.const 32))
        (call $emit (local.get $pstart) (i32.sub (local.get $pend) (local.get $pstart)))
        (call $emit (i32.const 272) (i32.const 3)))
      (else
        (call $emit (i32.const 96) (i32.const 66))
        (local.set $s (call $find (local.get $ptr) (local.get $len) (i32.const 48) (i32.const 12)))
        (if (i32.and (i32.ne (local.get $s) (i32.const -1)) (i32.gt_u (local.get $pend) (local.get $pstart)))
          (then
            (local.set $sstart (i32.add (local.get $s) (i32.const 12)))
            (local.set $send (call $string_end (local.get $sstart) (local.get $end)))
            ;; Tagged once only: skip subjects that already start with the prefix.
            (if (i32.ne
                  (call $find (local.get $sstart) (i32.sub (local.get $send) (local.get $sstart)) (local.get $pstart) (i32.sub (local.get $pend) (local.get $pstart)))
                  (local.get $sstart))
              (then
                (call $emit (i32.const 176) (i32.const 27))
                (call $emit (local.get $pstart) (i32.sub (local.get $pend) (local.get $pstart)))
                (call $emit (i32.const 288) (i32.const 1))
                (call $emit (local.get $sstart) (i32.sub (local.get $send) (local.get $sstart)))
                (call $emit (i32.const 208) (i32.const 3))))))
        (call $emit (i32.const 224) (i32.const 1))))

    (i64.or
      (i64.shl (i64.extend_i32_u (local.get $start)) (i64.const 32))
      (i64.extend_i32_u (i32.sub (global.get $out) (local.get $start))))))
