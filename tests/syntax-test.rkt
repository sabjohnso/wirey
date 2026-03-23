#lang racket/base

(require rackunit
         rackunit/spec
         racket/match
         wirey/field
         wirey/protocol
         wirey/syntax)

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
