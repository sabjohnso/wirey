#lang racket/base

(require wirey/stack
         wirey/protocols/ethernet
         wirey/protocols/ipv4
         wirey/protocols/tcp
         wirey/protocols/udp)

(provide (all-defined-out))

;; ============================================================
;; Common protocol stacks
;; ============================================================

;; Ethernet → IPv4 → TCP/UDP
(define-stack ethernet/ip-stack
  ethernet-header
  #:dispatch ethertype
  [(#x0800)
   ipv4-header
   #:dispatch protocol
   [(6)  tcp-header]
   [(17) udp-header]])
