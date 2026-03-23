#lang racket/base

(require rackunit
         rackunit/spec
         racket/match
         wirey/field
         wirey/protocol
         wirey/syntax
         wirey/length-expr
         wirey/checksum)

;; -- helpers --
(define (hex->bytes str)
  (define clean (regexp-replace* #rx" " str ""))
  (apply bytes
         (for/list ([i (in-range 0 (string-length clean) 2)])
           (string->number (substring clean i (+ i 2)) 16))))

;; Define a wire struct using the macro
(struct/wire system-event
  #:byte-order big
  (message-type  alpha  1)
  (stock-locate  uint   2)
  (tracking      uint   2)
  (timestamp     uint   6)
  (event-code    alpha  1))

(describe "struct/wire"
  (context "protocol descriptor"
    (it "creates a protocol-desc binding"
      (check-pred protocol-desc? system-event))

    (it "has the correct name"
      (check-eq? (protocol-desc-name system-event) 'system-event))

    (it "has the correct number of fields"
      (check-equal? (length (protocol-desc-fields system-event)) 5))

    (it "has the correct total size"
      (check-equal? (protocol-desc-total-size system-event) 12)))

  (context "encode with keyword arguments"
    (it "encodes values to bytes"
      (define bs (system-event-encode
                  #:message-type "S"
                  #:stock-locate 0
                  #:tracking     0
                  #:timestamp    #x00000E4E1C00
                  #:event-code   "O"))
      (check-equal? (bytes-length bs) 12)
      (check-equal? (bytes-ref bs 0) (char->integer #\S))
      (check-equal? (bytes-ref bs 11) (char->integer #\O))))

  (context "decode returns a struct with accessors"
    (it "produces a value satisfying the predicate"
      (define bs (bytes-append #"S"
                               (bytes 0 0)
                               (bytes 0 42)
                               (bytes 0 0 #x0E #x4E #x1C 0)
                               #"O"))
      (check-pred system-event? (system-event-decode bs)))

    (it "provides field accessors that decode from bytes"
      (define bs (bytes-append #"S"
                               (bytes 0 0)
                               (bytes 0 42)
                               (bytes 0 0 #x0E #x4E #x1C 0)
                               #"O"))
      (define v (system-event-decode bs))
      (check-equal? (system-event-message-type v) "S")
      (check-equal? (system-event-stock-locate v) 0)
      (check-equal? (system-event-tracking v) 42)
      (check-equal? (system-event-timestamp v) #x00000E4E1C00)
      (check-equal? (system-event-event-code v) "O"))

    (it "decodes with an offset"
      (define bs (bytes-append (bytes 0 0)  ; 2 bytes of padding
                               #"S"
                               (bytes 0 0)
                               (bytes 0 42)
                               (bytes 0 0 #x0E #x4E #x1C 0)
                               #"O"))
      (define v (system-event-decode bs #:offset 2))
      (check-equal? (system-event-message-type v) "S")
      (check-equal? (system-event-tracking v) 42)))

  (context "round-trip"
    (it "accessors on decoded encoded value return original values"
      (define bs (system-event-encode
                  #:message-type "S"
                  #:stock-locate 0
                  #:tracking     42
                  #:timestamp    #x00000E4E1C00
                  #:event-code   "O"))
      (define v (system-event-decode bs))
      (check-equal? (system-event-message-type v) "S")
      (check-equal? (system-event-stock-locate v) 0)
      (check-equal? (system-event-tracking v) 42)
      (check-equal? (system-event-timestamp v) #x00000E4E1C00)
      (check-equal? (system-event-event-code v) "O")))

  (context "match patterns"
    (it "binds only requested fields via keywords"
      (define bs (system-event-encode
                  #:message-type "S"
                  #:stock-locate 7
                  #:tracking     42
                  #:timestamp    #x00000E4E1C00
                  #:event-code   "O"))
      (define v (system-event-decode bs))
      (match v
        [(system-event #:tracking t #:event-code ec)
         (check-equal? t 42)
         (check-equal? ec "O")]))

    (it "works in match with predicate only (no fields)"
      (define bs (system-event-encode
                  #:message-type "S"
                  #:stock-locate 0
                  #:tracking     0
                  #:timestamp    0
                  #:event-code   "O"))
      (check-true
       (match (system-event-decode bs)
         [(system-event) #t]
         [_ #f])))

    (it "fails to match a non-matching value"
      (check-false
       (match "not-a-wire-struct"
         [(system-event) #t]
         [_ #f])))))

;; Test with little-endian default
(struct/wire pcap-record
  #:byte-order little
  (ts-sec    uint 4)
  (ts-usec   uint 4)
  (incl-len  uint 4)
  (orig-len  uint 4))

(describe "struct/wire with little-endian default"
  (it "encodes in little-endian"
    (define bs (pcap-record-encode
                #:ts-sec   #x01020304
                #:ts-usec  0
                #:incl-len 64
                #:orig-len 64))
    (check-equal? (bytes-ref bs 0) #x04)
    (check-equal? (bytes-ref bs 1) #x03)
    (check-equal? (bytes-ref bs 2) #x02)
    (check-equal? (bytes-ref bs 3) #x01))

  (it "decodes via accessors"
    (define bs (pcap-record-encode
                #:ts-sec   1000
                #:ts-usec  500
                #:incl-len 64
                #:orig-len 128))
    (define v (pcap-record-decode bs))
    (check-equal? (pcap-record-ts-sec v) 1000)
    (check-equal? (pcap-record-orig-len v) 128)))

;; Test per-field byte-order override
(struct/wire mixed-endian
  #:byte-order big
  (big-field    uint 2)
  (little-field uint 2 #:byte-order little))

(describe "struct/wire with per-field byte-order override"
  (it "uses the specified byte-order per field"
    (define bs (mixed-endian-encode
                #:big-field    #x0102
                #:little-field #x0304))
    ;; big-field: big-endian → 01 02
    (check-equal? (bytes-ref bs 0) #x01)
    (check-equal? (bytes-ref bs 1) #x02)
    ;; little-field: little-endian → 04 03
    (check-equal? (bytes-ref bs 2) #x04)
    (check-equal? (bytes-ref bs 3) #x03))

  (it "round-trips through accessors"
    (define bs (mixed-endian-encode
                #:big-field    #x0102
                #:little-field #x0304))
    (define v (mixed-endian-decode bs))
    (check-equal? (mixed-endian-big-field v) #x0102)
    (check-equal? (mixed-endian-little-field v) #x0304)))

;; Test bitfields in struct/wire
(struct/wire ipv4-start
  #:byte-order big
  (version      uint 4  #:unit bits)
  (ihl          uint 4  #:unit bits)
  (dscp         uint 6  #:unit bits)
  (ecn          uint 2  #:unit bits)
  (total-length uint 2))

(describe "struct/wire with bitfields"
  (context "encoding"
    (it "encodes bitfield nibbles and byte field"
      (define bs (ipv4-start-encode
                  #:version 4
                  #:ihl 5
                  #:dscp 0
                  #:ecn 0
                  #:total-length 1500))
      (check-equal? (bytes-ref bs 0) #x45)
      (check-equal? (bytes-ref bs 1) #x00)
      (check-equal? bs (bytes #x45 #x00 #x05 #xDC))))

  (context "decoding with accessors"
    (it "decodes bitfields correctly"
      (define v (ipv4-start-decode (bytes #x45 #x00 #x05 #xDC)))
      (check-equal? (ipv4-start-version v) 4)
      (check-equal? (ipv4-start-ihl v) 5)
      (check-equal? (ipv4-start-dscp v) 0)
      (check-equal? (ipv4-start-ecn v) 0)
      (check-equal? (ipv4-start-total-length v) 1500)))

  (context "round-trip"
    (it "encode then decode returns original values"
      (define bs (ipv4-start-encode
                  #:version 4 #:ihl 5
                  #:dscp 46 #:ecn 2
                  #:total-length 576))
      (define v (ipv4-start-decode bs))
      (check-equal? (ipv4-start-version v) 4)
      (check-equal? (ipv4-start-ihl v) 5)
      (check-equal? (ipv4-start-dscp v) 46)
      (check-equal? (ipv4-start-ecn v) 2)
      (check-equal? (ipv4-start-total-length v) 576)))

  (context "match patterns"
    (it "matches bitfield values"
      (define v (ipv4-start-decode (bytes #x45 #x00 #x05 #xDC)))
      (match v
        [(ipv4-start #:version ver #:total-length tl)
         (check-equal? ver 4)
         (check-equal? tl 1500)]))))

;; Test variable-length struct/wire
(struct/wire framed-msg
  #:byte-order big
  (tag   uint   1)
  (len   uint   2)
  (data  octets (field-ref len))
  (crc   uint   2))

(describe "struct/wire with variable-length fields"
  (context "encoding"
    (it "encodes with keyword args"
      (define bs (framed-msg-encode
                  #:tag  #xAA
                  #:len  3
                  #:data (bytes 1 2 3)
                  #:crc  #x1234))
      (check-equal? bs (bytes #xAA #x00 #x03 1 2 3 #x12 #x34))))

  (context "decoding with accessors"
    (it "decodes fixed and variable fields"
      (define v (framed-msg-decode (bytes #xAA #x00 #x03 1 2 3 #x12 #x34)))
      (check-equal? (framed-msg-tag v) #xAA)
      (check-equal? (framed-msg-len v) 3)
      (check-equal? (framed-msg-data v) (bytes 1 2 3))
      (check-equal? (framed-msg-crc v) #x1234))

    (it "handles different data lengths"
      (define v (framed-msg-decode (bytes #xBB #x00 #x01 #xFF #xDD #xEE)))
      (check-equal? (framed-msg-len v) 1)
      (check-equal? (framed-msg-data v) (bytes #xFF))
      (check-equal? (framed-msg-crc v) #xDDEE)))

  (context "round-trip"
    (it "encode then decode returns original values"
      (define bs (framed-msg-encode
                  #:tag  #xCC
                  #:len  4
                  #:data (bytes 10 20 30 40)
                  #:crc  #x5678))
      (define v (framed-msg-decode bs))
      (check-equal? (framed-msg-tag v) #xCC)
      (check-equal? (framed-msg-len v) 4)
      (check-equal? (framed-msg-data v) (bytes 10 20 30 40))
      (check-equal? (framed-msg-crc v) #x5678)))

  (context "match patterns"
    (it "matches variable-length struct fields"
      (define v (framed-msg-decode (bytes #xAA #x00 #x02 #xBB #xCC #xDD #xEE)))
      (match v
        [(framed-msg #:tag t #:data d #:crc c)
         (check-equal? t #xAA)
         (check-equal? d (bytes #xBB #xCC))
         (check-equal? c #xDDEE)]))))

;; Test computed fields in struct/wire
(define (simple-sum-checksum buf)
  (define total 0)
  (for ([i (in-range (bytes-length buf))])
    (set! total (+ total (bytes-ref buf i))))
  (modulo total 256))

(struct/wire checksummed-msg
  #:byte-order big
  (tag  uint 1)
  (data uint 2)
  (chk  uint 1 #:compute simple-sum-checksum))

(describe "struct/wire with computed fields"
  (context "encoding"
    (it "does not require computed field in keyword args"
      (define bs (checksummed-msg-encode #:tag #xAA #:data #x0102))
      (check-equal? (bytes-length bs) 4)
      ;; chk = (#xAA + #x01 + #x02 + 0) mod 256 = #xAD
      (check-equal? (bytes-ref bs 3) #xAD))

    (it "computes correct checksum"
      (define bs (checksummed-msg-encode #:tag #x10 #:data #x2030))
      ;; chk = (#x10 + #x20 + #x30 + 0) mod 256 = #x60
      (check-equal? (bytes-ref bs 3) #x60)))

  (context "decoding"
    (it "decodes computed fields normally"
      (define bs (checksummed-msg-encode #:tag #xAA #:data #x0102))
      (define v (checksummed-msg-decode bs))
      (check-equal? (checksummed-msg-tag v) #xAA)
      (check-equal? (checksummed-msg-data v) #x0102)
      (check-equal? (checksummed-msg-chk v) #xAD)))

  (context "match"
    (it "matches computed field values"
      (define bs (checksummed-msg-encode #:tag #xAA #:data #x0102))
      (match (checksummed-msg-decode bs)
        [(checksummed-msg #:tag t #:chk c)
         (check-equal? t #xAA)
         (check-equal? c #xAD)]))))

;; Test contracts in struct/wire
(define (valid-port? v) (and (integer? v) (<= 0 v 65535)))
(define (positive? v) (> v 0))

(struct/wire contracted-msg
  #:byte-order big
  (port  uint 2 #:contract valid-port?)
  (count uint 1 #:contract positive?)
  (data  uint 1))

(describe "struct/wire with contracts"
  (context "encoding"
    (it "succeeds when contracts are satisfied"
      (check-not-exn
       (λ () (contracted-msg-encode #:port 80 #:count 5 #:data 0))))

    (it "raises when port contract violated"
      (check-exn exn:fail?
        (λ () (contracted-msg-encode #:port 70000 #:count 1 #:data 0))))

    (it "raises when count contract violated"
      (check-exn exn:fail?
        (λ () (contracted-msg-encode #:port 80 #:count 0 #:data 0)))))

  (context "decoding"
    (it "decodes normally regardless of contracts"
      ;; Decode always works — contracts are encode-time only by default
      (define bs (bytes #x00 #x50 #x03 #xFF))
      (define v (contracted-msg-decode bs))
      (check-equal? (contracted-msg-port v) 80)
      (check-equal? (contracted-msg-count v) 3)
      (check-equal? (contracted-msg-data v) #xFF))))
