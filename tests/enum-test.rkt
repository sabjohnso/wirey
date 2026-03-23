#lang racket/base

(require rackunit
         rackunit/spec
         wirey/enum)

;; Define a test enum
(define-wire-enum ip-protocol
  [tcp    6]
  [udp   17]
  [icmp   1])

(describe "define-wire-enum"
  (it "creates a wire-enum"
    (check-pred wire-enum? ip-protocol))

  (it "looks up symbol → integer"
    (check-equal? (wire-enum-ref ip-protocol 'tcp) 6)
    (check-equal? (wire-enum-ref ip-protocol 'udp) 17)
    (check-equal? (wire-enum-ref ip-protocol 'icmp) 1))

  (it "passes through raw integers"
    (check-equal? (wire-enum-ref ip-protocol 6) 6)
    (check-equal? (wire-enum-ref ip-protocol 99) 99))

  (it "looks up integer → symbol"
    (check-equal? (wire-enum-lookup ip-protocol 6) 'tcp)
    (check-equal? (wire-enum-lookup ip-protocol 17) 'udp)
    (check-equal? (wire-enum-lookup ip-protocol 1) 'icmp))

  (it "returns raw integer for unknown values"
    (check-equal? (wire-enum-lookup ip-protocol 99) 99))

  (it "lists all entries"
    (check-equal? (length (wire-enum-entries ip-protocol)) 3)))

;; Second enum
(define-wire-enum ethertype
  [ipv4  #x0800]
  [ipv6  #x86DD]
  [arp   #x0806])

(describe "ethertype enum"
  (it "encodes and decodes correctly"
    (check-equal? (wire-enum-ref ethertype 'ipv4) #x0800)
    (check-equal? (wire-enum-lookup ethertype #x0800) 'ipv4)
    (check-equal? (wire-enum-lookup ethertype #xFFFF) #xFFFF)))
