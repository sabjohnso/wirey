#lang racket/base

(require rackunit
         rackunit/spec
         racket/match
         wirey/syntax
         wirey/protocol
         wirey/stack
         wirey/protocols/ethernet
         wirey/protocols/ipv4
         wirey/protocols/tcp
         wirey/protocols/udp
         wirey/protocols/stacks)

;; -- Define simple wire structs for testing --

(struct/wire test-frame
  #:byte-order big
  (dst     octets 2)
  (src     octets 2)
  (type    uint   2))

(struct/wire test-ipv4
  #:byte-order big
  (version uint 4 #:unit bits)
  (ihl     uint 4 #:unit bits)
  (total   uint 2)
  (proto   uint 1)
  (src-ip  uint 4)
  (dst-ip  uint 4))

(struct/wire test-tcp
  #:byte-order big
  (src-port uint 2)
  (dst-port uint 2))

(struct/wire test-udp
  #:byte-order big
  (src-port uint 2)
  (dst-port uint 2)
  (length   uint 2)
  (checksum uint 2))

;; -- Stack descriptor --

(define sd
  (make-stack-desc 'test-stack
    (list
     (make-layer test-frame test-frame-decode
                 'type test-frame-type
                 (list (cons #x0800 'ipv4-layer)))
     (make-layer/named 'ipv4-layer test-ipv4 test-ipv4-decode
                       'proto test-ipv4-proto
                       (list (cons 6 'tcp-layer)
                             (cons 17 'udp-layer)))
     (make-layer/named 'tcp-layer test-tcp test-tcp-decode
                       #f #f '())
     (make-layer/named 'udp-layer test-udp test-udp-decode
                       #f #f '()))))

;; -- Test packets --

(define frame-bytes
  (test-frame-encode #:dst (bytes 1 2) #:src (bytes 3 4) #:type #x0800))

(define ipv4-tcp-bytes
  (test-ipv4-encode #:version 4 #:ihl 3 #:total 16 #:proto 6
                    #:src-ip #xC0A80101 #:dst-ip #x0A000001))

(define tcp-bytes
  (test-tcp-encode #:src-port 80 #:dst-port 49152))

(define tcp-pkt (bytes-append frame-bytes ipv4-tcp-bytes tcp-bytes))

(define ipv4-udp-bytes
  (test-ipv4-encode #:version 4 #:ihl 3 #:total 20 #:proto 17
                    #:src-ip #x08080808 #:dst-ip #xC0A80101))

(define udp-bytes
  (test-udp-encode #:src-port 53 #:dst-port 12345 #:length 8 #:checksum 0))

(define udp-pkt (bytes-append frame-bytes ipv4-udp-bytes udp-bytes))

;; -- Tests --

(describe "make-stack-desc"
  (it "creates a stack descriptor"
    (check-pred stack-desc? sd)
    (check-eq? (stack-desc-name sd) 'test-stack)))

(describe "stack-decode"
  (context "TCP packet"
    (it "decodes a multi-layer packet"
      (define result (stack-decode sd tcp-pkt))
      (check-pred stack-value? result))

    (it "provides access to each layer via stack-ref"
      (define result (stack-decode sd tcp-pkt))
      (define frame-layer (stack-ref result test-frame?))
      (define ipv4-layer (stack-ref result test-ipv4?))
      (define tcp-layer (stack-ref result test-tcp?))
      (check-equal? (test-frame-type frame-layer) #x0800)
      (check-equal? (test-ipv4-proto ipv4-layer) 6)
      (check-equal? (test-ipv4-src-ip ipv4-layer) #xC0A80101)
      (check-equal? (test-tcp-src-port tcp-layer) 80)
      (check-equal? (test-tcp-dst-port tcp-layer) 49152))

    (it "does not contain UDP layer"
      (define result (stack-decode sd tcp-pkt))
      (check-false (stack-ref result test-udp?))))

  (context "UDP packet"
    (it "dispatches to the correct layer based on field values"
      (define result (stack-decode sd udp-pkt))
      (check-false (stack-ref result test-tcp?))
      (define udp-layer (stack-ref result test-udp?))
      (check-equal? (test-udp-src-port udp-layer) 53)
      (check-equal? (test-udp-dst-port udp-layer) 12345))))

;; ===== define-stack macro =====

(define-stack test-net-stack
  test-frame
  #:dispatch type
  [(#x0800)
   test-ipv4
   #:dispatch proto
   [(6) test-tcp]
   [(17) test-udp]])

(describe "define-stack macro"
  (it "creates a stack descriptor"
    (check-pred stack-desc? test-net-stack))

  (it "generates a decode function"
    (define result (test-net-stack-decode tcp-pkt))
    (check-pred stack-value? result))

  (it "decodes TCP packets correctly"
    (define result (test-net-stack-decode tcp-pkt))
    (define tcp-layer (stack-ref result test-tcp?))
    (check-equal? (test-tcp-src-port tcp-layer) 80)
    (check-equal? (test-tcp-dst-port tcp-layer) 49152))

  (it "decodes UDP packets correctly"
    (define result (test-net-stack-decode udp-pkt))
    (define udp-layer (stack-ref result test-udp?))
    (check-equal? (test-udp-src-port udp-layer) 53))

  (it "supports stack-ref with wire struct predicates"
    (define result (test-net-stack-decode tcp-pkt))
    (define frame (stack-ref result test-frame?))
    (define ip (stack-ref result test-ipv4?))
    (define tcp (stack-ref result test-tcp?))
    (check-equal? (test-frame-type frame) #x0800)
    (check-equal? (test-ipv4-src-ip ip) #xC0A80101)
    (check-equal? (test-tcp-dst-port tcp) 49152))

  (it "composes with wire struct match patterns via stack-ref"
    (define result (test-net-stack-decode tcp-pkt))
    (match (stack-ref result test-ipv4?)
      [(test-ipv4 #:src-ip src #:proto p)
       (check-equal? src #xC0A80101)
       (check-equal? p 6)])
    (match (stack-ref result test-tcp?)
      [(test-tcp #:dst-port dp)
       (check-equal? dp 49152)])))

;; ===== Real protocol stack tests =====

(define (hex->bytes str)
  (define clean (regexp-replace* #rx" " str ""))
  (apply bytes
         (for/list ([i (in-range 0 (string-length clean) 2)])
           (string->number (substring clean i (+ i 2)) 16))))

(describe "ethernet/ip-stack"
  ;; Build a real Ethernet + IPv4 + TCP packet
  (define eth-bytes
    (ethernet-header-encode
     #:dst-mac (hex->bytes "FF FF FF FF FF FF")
     #:src-mac (hex->bytes "00 1A 2B 3C 4D 5E")
     #:ethertype #x0800))
  (define ip-bytes
    (ipv4-header-encode
     #:version 4 #:ihl 5
     #:dscp 0 #:ecn 0
     #:total-length 40
     #:identification #xABCD
     #:flags 2 #:fragment-offset 0
     #:ttl 64 #:protocol 6
     #:header-checksum 0
     #:src-ip #xC0A80101
     #:dst-ip #x0A000001))
  (define tcp-bytes*
    (tcp-header-encode
     #:src-port 80 #:dst-port 49152
     #:seq-number 1000 #:ack-number 0
     #:data-offset 5 #:reserved 0
     #:ns 0 #:cwr 0 #:ece 0 #:urg 0
     #:ack 0 #:psh 0 #:rst 0 #:syn 1 #:fin 0
     #:window-size 65535
     #:checksum 0 #:urgent-ptr 0))
  (define real-tcp-pkt (bytes-append eth-bytes ip-bytes tcp-bytes*))

  (it "decodes Ethernet → IPv4 → TCP"
    (define result (ethernet/ip-stack-decode real-tcp-pkt))
    (define eth (stack-ref result ethernet-header?))
    (define ip (stack-ref result ipv4-header?))
    (define tcp (stack-ref result tcp-header?))
    (check-equal? (ethernet-header-ethertype eth) #x0800)
    (check-equal? (ipv4-header-version ip) 4)
    (check-equal? (ipv4-header-protocol ip) 6)
    (check-equal? (ipv4-header-src-ip ip) #xC0A80101)
    (check-equal? (tcp-header-src-port tcp) 80)
    (check-equal? (tcp-header-syn tcp) 1))

  ;; Build Ethernet + IPv4 + UDP
  (define udp-ip-bytes
    (ipv4-header-encode
     #:version 4 #:ihl 5
     #:dscp 0 #:ecn 0
     #:total-length 28
     #:identification #x1234
     #:flags 0 #:fragment-offset 0
     #:ttl 128 #:protocol 17
     #:header-checksum 0
     #:src-ip #x08080808
     #:dst-ip #xC0A80101))
  (define udp-bytes*
    (udp-header-encode
     #:src-port 53 #:dst-port 12345
     #:length 8 #:checksum 0))
  (define real-udp-pkt (bytes-append eth-bytes udp-ip-bytes udp-bytes*))

  (it "decodes Ethernet → IPv4 → UDP"
    (define result (ethernet/ip-stack-decode real-udp-pkt))
    (define eth (stack-ref result ethernet-header?))
    (define ip (stack-ref result ipv4-header?))
    (define udp (stack-ref result udp-header?))
    (check-equal? (ethernet-header-ethertype eth) #x0800)
    (check-equal? (ipv4-header-protocol ip) 17)
    (check-equal? (udp-header-src-port udp) 53)
    (check-equal? (udp-header-dst-port udp) 12345)))
