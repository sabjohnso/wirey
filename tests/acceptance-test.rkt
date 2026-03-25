#lang racket/base

(require rackunit
         rackunit/spec
         racket/list
         racket/match
         wirey/syntax2
         wirey/ir
         wirey/ir-codec)

(define (hex->bytes str)
  (define clean (regexp-replace* #rx" " str ""))
  (apply bytes
         (for/list ([i (in-range 0 (string-length clean) 2)])
           (string->number (substring clean i (+ i 2)) 16))))

;; ============================================================
;; TARGET 1: ITCH System Event (fixed-layout, alpha + uint)
;; ============================================================

(struct/wire itch-system-event
  #:byte-order big
  (message-type  alpha  1)
  (stock-locate  uint   2)
  (tracking      uint   2)
  (timestamp     uint   6)
  (event-code    alpha  1))

(describe "Acceptance: ITCH system event"
  (it "size = 12 bytes"
    (define bs (itch-system-event-encode
                 #:message-type "S" #:stock-locate 0 #:tracking 0
                 #:timestamp #x00000E4E1C00 #:event-code "O"))
    (check-equal? (bytes-length bs) 12))

  (it "round-trips"
    (define bs (itch-system-event-encode
                 #:message-type "S" #:stock-locate 0 #:tracking 42
                 #:timestamp #x00000E4E1C00 #:event-code "O"))
    (define v (itch-system-event-decode bs))
    (check-equal? (itch-system-event-message-type v) "S")
    (check-equal? (itch-system-event-tracking v) 42)
    (check-equal? (itch-system-event-event-code v) "O"))

  (it "match"
    (define v (itch-system-event-decode
                (itch-system-event-encode
                  #:message-type "S" #:stock-locate 0 #:tracking 0
                  #:timestamp 0 #:event-code "O")))
    (match v
      [(itch-system-event #:event-code ec)
       (check-equal? ec "O")])))

;; ============================================================
;; TARGET 2: ITCH Add Order (36 bytes, with 8-byte alpha stock)
;; ============================================================

(struct/wire itch-add-order
  #:byte-order big
  (message-type  alpha  1)
  (stock-locate  uint   2)
  (tracking      uint   2)
  (timestamp     uint   6)
  (order-ref     uint   8)
  (buy-sell      alpha  1)
  (shares        uint   4)
  (stock         alpha  8)
  (price         uint   4))

(describe "Acceptance: ITCH add order"
  (it "size = 36 bytes"
    (define bs (itch-add-order-encode
                 #:message-type "A" #:stock-locate 1 #:tracking 0
                 #:timestamp #x0000094F7A00 #:order-ref 12345678
                 #:buy-sell "B" #:shares 100 #:stock "AAPL" #:price 1500000))
    (check-equal? (bytes-length bs) 36))

  (it "round-trips stock name"
    (define bs (itch-add-order-encode
                 #:message-type "A" #:stock-locate 1 #:tracking 0
                 #:timestamp 0 #:order-ref 1 #:buy-sell "B"
                 #:shares 100 #:stock "AAPL" #:price 1500000))
    (define v (itch-add-order-decode bs))
    (check-equal? (itch-add-order-stock v) "AAPL")
    (check-equal? (itch-add-order-shares v) 100)))

;; ============================================================
;; TARGET 3: MoldUDP64 (variable-length message block)
;; ============================================================

(struct/wire moldudp64-block
  #:byte-order big
  (message-length uint 2)
  (message-data   octets (field-ref message-length)))

(describe "Acceptance: MoldUDP64 message block"
  (it "encodes length-prefixed data"
    (define bs (moldudp64-block-encode #:message-length 3
                                       #:message-data (bytes 1 2 3)))
    (check-equal? bs (bytes 0 3 1 2 3)))

  (it "round-trips"
    (define bs (moldudp64-block-encode #:message-length 4
                                       #:message-data (bytes 10 20 30 40)))
    (define v (moldudp64-block-decode bs))
    (check-equal? (moldudp64-block-message-length v) 4)
    (check-equal? (moldudp64-block-message-data v) (bytes 10 20 30 40))))

;; ============================================================
;; TARGET 4: IPv4 header (bitfields)
;; ============================================================

(struct/wire ipv4-hdr
  #:byte-order big
  (version          uint 4  #:unit bits)
  (ihl              uint 4  #:unit bits)
  (dscp             uint 6  #:unit bits)
  (ecn              uint 2  #:unit bits)
  (total-length     uint 2)
  (identification   uint 2)
  (flags            uint 3  #:unit bits)
  (fragment-offset  uint 13 #:unit bits)
  (ttl              uint 1)
  (protocol         uint 1)
  (header-checksum  uint 2)
  (src-ip           uint 4)
  (dst-ip           uint 4))

(describe "Acceptance: IPv4 header"
  (it "decodes known header"
    (define raw (hex->bytes
                 "45 00 05 DC AB CD 40 00 40 06 00 00 C0 A8 01 01 0A 00 00 01"))
    (define v (ipv4-hdr-decode raw))
    (check-equal? (ipv4-hdr-version v) 4)
    (check-equal? (ipv4-hdr-ihl v) 5)
    (check-equal? (ipv4-hdr-total-length v) 1500)
    (check-equal? (ipv4-hdr-flags v) 2)
    (check-equal? (ipv4-hdr-protocol v) 6)
    (check-equal? (ipv4-hdr-src-ip v) #xC0A80101))

  (it "round-trips"
    (define v (hasheq 'version 4 'ihl 5 'dscp 0 'ecn 0
                      'total-length 1500 'identification #xABCD
                      'flags 2 'fragment-offset 0 'ttl 64 'protocol 6
                      'header-checksum 0 'src-ip #xC0A80101 'dst-ip #x0A000001))
    (define bs (ir-encode ipv4-hdr v))
    (check-equal? (ir-decode ipv4-hdr bs) v)))

;; ============================================================
;; TARGET 5: CBOR (self-describing, recursive via #:encode/#:decode)
;; ============================================================

;; Forward declarations for recursive encode
(define (cbor-argument->ai+ext arg)
  (cond [(<= arg 23) (values arg #f)]
        [(<= arg #xFF) (values 24 arg)]
        [(<= arg #xFFFF) (values 25 arg)]
        [(<= arg #xFFFFFFFF) (values 26 arg)]
        [else (values 27 arg)]))

(define (cbor-make-head mt arg)
  (define-values (ai ext) (cbor-argument->ai+ext arg))
  (if ext (hasheq 'major-type mt 'additional-info ai 'ext-arg ext)
      (hasheq 'major-type mt 'additional-info ai)))

(define (cbor-racket->fields v)
  (cond
    [(eq? v #t) (hasheq 'major-type 7 'additional-info 21)]
    [(eq? v #f) (hasheq 'major-type 7 'additional-info 20)]
    [(eq? v 'null) (hasheq 'major-type 7 'additional-info 22)]
    [(and (integer? v) (exact? v) (>= v 0)) (cbor-make-head 0 v)]
    [(and (integer? v) (exact? v) (< v 0)) (cbor-make-head 1 (- -1 v))]
    [(bytes? v)
     (hash-set (cbor-make-head 2 (bytes-length v)) 'payload v)]
    [(string? v)
     (define utf8 (string->bytes/utf-8 v))
     (hash-set (cbor-make-head 3 (bytes-length utf8)) 'payload utf8)]
    [(list? v)
     (define item-bytes (apply bytes-append (map cbor-item-encode-value v)))
     (hash-set (cbor-make-head 4 (length v)) 'items item-bytes)]
    [else (error 'cbor-encode "unsupported: ~e" v)]))

(define (cbor-fields->racket h)
  (define mt (hash-ref h 'major-type))
  (define ai (hash-ref h 'additional-info))
  (define arg (or (hash-ref h 'ext-arg #f) ai))
  (case mt
    [(0) arg]
    [(1) (- -1 arg)]
    [(2) (hash-ref h 'payload (bytes))]
    [(3) (bytes->string/utf-8 (hash-ref h 'payload (bytes)))]
    [(4) ;; Decode items from raw bytes
     (define raw (hash-ref h 'items #f))
     (if (and raw (bytes? raw) (> (bytes-length raw) 0))
         (let loop ([off 0] [n arg] [acc '()])
           (if (zero? n) (reverse acc)
               (let ()
                 (define item-val (cbor-item-decode-value raw #:offset off))
                 (define item-h (ir-decode cbor-item raw #:offset off))
                 ;; Compute consumed bytes
                 (define consumed (- (bytes-length (ir-encode cbor-item item-h)) 0))
                 ;; Actually need offset advancement — use ir-decode internals
                 ;; For now: re-encode to measure size
                 (define item-bs (ir-encode cbor-item item-h))
                 (loop (+ off (bytes-length item-bs)) (sub1 n) (cons item-val acc)))))
         '())]
    [(7) (cond [(= ai 20) #f] [(= ai 21) #t] [(= ai 22) 'null]
               [else arg])]))

(struct/wire cbor-item
  #:byte-order big
  #:encode cbor-racket->fields
  #:decode cbor-fields->racket
  (major-type       uint 3 #:unit bits)
  (additional-info  uint 5 #:unit bits)
  (#:case additional-info
    [((λ (v) (<= v 23)))]
    [(24) (ext-arg uint 1)]
    [(25) (ext-arg uint 2)]
    [(26) (ext-arg uint 4)]
    [(27) (ext-arg uint 8)])
  (#:case major-type
    [(0)] [(1)]
    [(2) (payload octets (compute (λ (lk) (or (lk 'ext-arg) (lk 'additional-info)))))]
    [(3) (payload octets (compute (λ (lk) (or (lk 'ext-arg) (lk 'additional-info)))))]
    [(4) (items octets
            (compute (λ (lk)
                       (define v (lk 'items))
                       (if (and v (bytes? v)) (bytes-length v) 0))))]
    [(7)]))

(describe "Acceptance: CBOR via struct/wire"
  (it "encode-value unsigned 0"
    (check-equal? (cbor-item-encode-value 0) (bytes #x00)))
  (it "encode-value unsigned 24"
    (check-equal? (cbor-item-encode-value 24) (bytes #x18 #x18)))
  (it "encode-value unsigned 1000"
    (check-equal? (cbor-item-encode-value 1000) (bytes #x19 #x03 #xE8)))
  (it "encode-value negative -1"
    (check-equal? (cbor-item-encode-value -1) (bytes #x20)))
  (it "encode-value negative -100"
    (check-equal? (cbor-item-encode-value -100) (bytes #x38 #x63)))
  (it "encode-value text \"IETF\""
    (check-equal? (cbor-item-encode-value "IETF")
                  (bytes #x64 #x49 #x45 #x54 #x46)))
  (it "encode-value bytes"
    (check-equal? (cbor-item-encode-value (bytes 1 2 3 4))
                  (bytes #x44 1 2 3 4)))
  (it "encode-value false"
    (check-equal? (cbor-item-encode-value #f) (bytes #xF4)))
  (it "encode-value true"
    (check-equal? (cbor-item-encode-value #t) (bytes #xF5)))
  (it "encode-value null"
    (check-equal? (cbor-item-encode-value 'null) (bytes #xF6)))

  (it "decode-value unsigned"
    (check-equal? (cbor-item-decode-value (bytes #x00)) 0)
    (check-equal? (cbor-item-decode-value (bytes #x18 #x18)) 24)
    (check-equal? (cbor-item-decode-value (bytes #x19 #x03 #xE8)) 1000))

  (it "decode-value negative"
    (check-equal? (cbor-item-decode-value (bytes #x20)) -1)
    (check-equal? (cbor-item-decode-value (bytes #x38 #x63)) -100))

  (it "decode-value text"
    (check-equal? (cbor-item-decode-value (bytes #x64 #x49 #x45 #x54 #x46)) "IETF"))

  (it "decode-value simple"
    (check-equal? (cbor-item-decode-value (bytes #xF4)) #f)
    (check-equal? (cbor-item-decode-value (bytes #xF5)) #t)
    (check-equal? (cbor-item-decode-value (bytes #xF6)) 'null))

  (it "round-trip integers"
    (for ([n (list 0 1 23 24 100 1000 1000000)])
      (check-equal? (cbor-item-decode-value (cbor-item-encode-value n)) n))
    (for ([n (list -1 -10 -100 -1000)])
      (check-equal? (cbor-item-decode-value (cbor-item-encode-value n)) n)))

  (it "round-trip strings"
    (for ([s (list "" "a" "IETF" "hello")])
      (check-equal? (cbor-item-decode-value (cbor-item-encode-value s)) s)))

  (it "round-trip byte strings"
    (for ([bs (list (bytes) (bytes 1 2 3))])
      (check-equal? (cbor-item-decode-value (cbor-item-encode-value bs)) bs)))

  (it "encode-value array [1, 2, 3]"
    (check-equal? (cbor-item-encode-value '(1 2 3))
                  (bytes #x83 #x01 #x02 #x03))))
