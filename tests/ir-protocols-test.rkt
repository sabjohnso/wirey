#lang racket/base

(require rackunit
         rackunit/spec
         racket/list
         wirey/ir
         wirey/ir-codec)

(define (hex->bytes str)
  (define clean (regexp-replace* #rx" " str ""))
  (apply bytes
         (for/list ([i (in-range 0 (string-length clean) 2)])
           (string->number (substring clean i (+ i 2)) 16))))

;; ============================================================
;; UDP header — simplest fixed-layout protocol
;; ============================================================

(define udp-header
  (wire-protocol 'udp-header
    (list (wire-field 'src-port  'uint (width-fixed 2) 'big (hasheq))
          (wire-field 'dst-port  'uint (width-fixed 2) 'big (hasheq))
          (wire-field 'length    'uint (width-fixed 2) 'big (hasheq))
          (wire-field 'checksum  'uint (width-fixed 2) 'big (hasheq)))
    (hasheq)))

(describe "UDP header on new IR"
  (it "encodes"
    (define bs (ir-encode udp-header
                 (hasheq 'src-port 49152 'dst-port 53 'length 42 'checksum 0)))
    (check-equal? (bytes-length bs) 8)
    ;; dst-port 53 = 0x0035
    (check-equal? (bytes-ref bs 2) #x00)
    (check-equal? (bytes-ref bs 3) #x35))

  (it "decodes"
    (define h (ir-decode udp-header (bytes #xC0 #x00 #x00 #x35 #x00 #x2A #x00 #x00)))
    (check-equal? (hash-ref h 'src-port) #xC000)
    (check-equal? (hash-ref h 'dst-port) 53)
    (check-equal? (hash-ref h 'length) 42))

  (it "round-trips"
    (define v (hasheq 'src-port 49152 'dst-port 80 'length 100 'checksum #xABCD))
    (check-equal? (ir-decode udp-header (ir-encode udp-header v)) v)))

;; ============================================================
;; IPv4 header — bitfields
;; ============================================================

(define ipv4-header
  (wire-protocol 'ipv4-header
    (list (wire-bitfield-group
            (list (wire-bit-field 'version 'uint 4 (hasheq))
                  (wire-bit-field 'ihl     'uint 4 (hasheq)))
            'msb 8)
          (wire-bitfield-group
            (list (wire-bit-field 'dscp 'uint 6 (hasheq))
                  (wire-bit-field 'ecn  'uint 2 (hasheq)))
            'msb 8)
          (wire-field 'total-length     'uint (width-fixed 2) 'big (hasheq))
          (wire-field 'identification   'uint (width-fixed 2) 'big (hasheq))
          (wire-bitfield-group
            (list (wire-bit-field 'flags           'uint 3  (hasheq))
                  (wire-bit-field 'fragment-offset 'uint 13 (hasheq)))
            'msb 16)
          (wire-field 'ttl              'uint (width-fixed 1) 'big (hasheq))
          (wire-field 'protocol         'uint (width-fixed 1) 'big (hasheq))
          (wire-field 'header-checksum  'uint (width-fixed 2) 'big (hasheq))
          (wire-field 'src-ip           'uint (width-fixed 4) 'big (hasheq))
          (wire-field 'dst-ip           'uint (width-fixed 4) 'big (hasheq)))
    (hasheq)))

(describe "IPv4 header on new IR"
  (it "decodes a known header"
    (define raw (hex->bytes
                 "45 00 05 DC AB CD 40 00 40 06 00 00 C0 A8 01 01 0A 00 00 01"))
    (define h (ir-decode ipv4-header raw))
    (check-equal? (hash-ref h 'version) 4)
    (check-equal? (hash-ref h 'ihl) 5)
    (check-equal? (hash-ref h 'total-length) 1500)
    (check-equal? (hash-ref h 'flags) 2)
    (check-equal? (hash-ref h 'fragment-offset) 0)
    (check-equal? (hash-ref h 'ttl) 64)
    (check-equal? (hash-ref h 'protocol) 6)
    (check-equal? (hash-ref h 'src-ip) #xC0A80101)
    (check-equal? (hash-ref h 'dst-ip) #x0A000001))

  (it "round-trips"
    (define v (hasheq 'version 4 'ihl 5 'dscp 0 'ecn 0
                      'total-length 1500 'identification #xABCD
                      'flags 2 'fragment-offset 0
                      'ttl 64 'protocol 6 'header-checksum 0
                      'src-ip #xC0A80101 'dst-ip #x0A000001))
    (check-equal? (ir-decode ipv4-header (ir-encode ipv4-header v)) v)))

;; ============================================================
;; Ethernet header — octets fields
;; ============================================================

(define ethernet-header
  (wire-protocol 'ethernet-header
    (list (wire-field 'dst-mac    'octets (width-fixed 6) 'big (hasheq))
          (wire-field 'src-mac    'octets (width-fixed 6) 'big (hasheq))
          (wire-field 'ethertype  'uint   (width-fixed 2) 'big (hasheq)))
    (hasheq)))

(describe "Ethernet header on new IR"
  (it "round-trips"
    (define v (hasheq 'dst-mac (bytes 1 2 3 4 5 6)
                      'src-mac (bytes 7 8 9 10 11 12)
                      'ethertype #x0800))
    (check-equal? (ir-decode ethernet-header (ir-encode ethernet-header v)) v)))

;; ============================================================
;; ITCH system event — alpha fields
;; ============================================================

(define itch-system-event
  (wire-protocol 'itch-system-event
    (list (wire-field 'message-type 'alpha (width-fixed 1) 'big (hasheq))
          (wire-field 'stock-locate 'uint  (width-fixed 2) 'big (hasheq))
          (wire-field 'tracking     'uint  (width-fixed 2) 'big (hasheq))
          (wire-field 'timestamp    'uint  (width-fixed 6) 'big (hasheq))
          (wire-field 'event-code   'alpha (width-fixed 1) 'big (hasheq)))
    (hasheq)))

(describe "ITCH system event on new IR"
  (it "round-trips"
    (define v (hasheq 'message-type "S" 'stock-locate 0 'tracking 0
                      'timestamp #x00000E4E1C00 'event-code "O"))
    (check-equal? (ir-decode itch-system-event (ir-encode itch-system-event v)) v)))

;; ============================================================
;; MoldUDP64 message block — variable-length
;; ============================================================

(define moldudp64-message-block
  (wire-protocol 'moldudp64-message-block
    (list (wire-field 'message-length 'uint   (width-fixed 2) 'big (hasheq))
          (wire-field 'message-data   'octets (width-field-ref 'message-length) 'big (hasheq)))
    (hasheq)))

(describe "MoldUDP64 message block on new IR"
  (it "encodes"
    (define bs (ir-encode moldudp64-message-block
                 (hasheq 'message-length 3 'message-data (bytes 1 2 3))))
    (check-equal? bs (bytes 0 3 1 2 3)))

  (it "decodes"
    (define h (ir-decode moldudp64-message-block (bytes 0 4 #xDE #xAD #xBE #xEF)))
    (check-equal? (hash-ref h 'message-length) 4)
    (check-equal? (hash-ref h 'message-data) (bytes #xDE #xAD #xBE #xEF)))

  (it "round-trips"
    (define v (hasheq 'message-length 5 'message-data (bytes 1 2 3 4 5)))
    (check-equal? (ir-decode moldudp64-message-block
                    (ir-encode moldudp64-message-block v)) v)))

;; ============================================================
;; CBOR-like: bitfields + case dispatch + variable-length + recursion
;; ============================================================

(define cbor-simple
  (wire-protocol 'cbor-simple
    (list (wire-bitfield-group
            (list (wire-bit-field 'major-type      'uint 3 (hasheq))
                  (wire-bit-field 'additional-info 'uint 5 (hasheq)))
            'msb 8)
          (wire-case 'additional-info
            (list (wire-case-branch (λ (v) (<= v 23)) '())
                  (wire-case-branch 24
                    (list (wire-field 'ext-arg 'uint (width-fixed 1) 'big (hasheq))))
                  (wire-case-branch 25
                    (list (wire-field 'ext-arg 'uint (width-fixed 2) 'big (hasheq))))
                  (wire-case-branch 26
                    (list (wire-field 'ext-arg 'uint (width-fixed 4) 'big (hasheq))))
                  (wire-case-branch 27
                    (list (wire-field 'ext-arg 'uint (width-fixed 8) 'big (hasheq))))))
          (wire-case 'major-type
            (list (wire-case-branch 0 '())  ;; unsigned int
                  (wire-case-branch 1 '())  ;; negative int
                  (wire-case-branch 2       ;; byte string
                    (list (wire-field 'payload 'octets
                            (width-compute
                              (λ (lk) (or (lk 'ext-arg) (lk 'additional-info))))
                            'big (hasheq))))
                  (wire-case-branch 3       ;; text string
                    (list (wire-field 'payload 'octets
                            (width-compute
                              (λ (lk) (or (lk 'ext-arg) (lk 'additional-info))))
                            'big (hasheq))))
                  (wire-case-branch 7 '())))) ;; simple/float
    (hasheq)))

(describe "CBOR-like on new IR"
  (it "decodes unsigned 0"
    (define h (ir-decode cbor-simple (bytes #x00)))
    (check-equal? (hash-ref h 'major-type) 0)
    (check-equal? (hash-ref h 'additional-info) 0))

  (it "decodes unsigned 1000"
    (define h (ir-decode cbor-simple (bytes #x19 #x03 #xE8)))
    (check-equal? (hash-ref h 'major-type) 0)
    (check-equal? (hash-ref h 'additional-info) 25)
    (check-equal? (hash-ref h 'ext-arg) 1000))

  (it "decodes text 'IETF'"
    (define h (ir-decode cbor-simple (bytes #x64 #x49 #x45 #x54 #x46)))
    (check-equal? (hash-ref h 'major-type) 3)
    (check-equal? (hash-ref h 'payload) #"IETF"))

  (it "decodes negative -100"
    (define h (ir-decode cbor-simple (bytes #x38 #x63)))
    (check-equal? (hash-ref h 'major-type) 1)
    (check-equal? (hash-ref h 'ext-arg) 99))

  (it "decodes false"
    (define h (ir-decode cbor-simple (bytes #xF4)))
    (check-equal? (hash-ref h 'major-type) 7)
    (check-equal? (hash-ref h 'additional-info) 20))

  (it "round-trips unsigned 24"
    (define v (hasheq 'major-type 0 'additional-info 24 'ext-arg 24))
    (check-equal? (ir-decode cbor-simple (ir-encode cbor-simple v)) v))

  (it "round-trips text"
    (define v (hasheq 'major-type 3 'additional-info 4 'payload #"IETF"))
    (check-equal? (ir-decode cbor-simple (ir-encode cbor-simple v)) v)))

;; ============================================================
;; Padding
;; ============================================================

(define padded-protocol
  (wire-protocol 'padded
    (list (wire-field   'tag 'uint (width-fixed 1) 'big (hasheq))
          (wire-padding (width-fixed 3))
          (wire-field   'val 'uint (width-fixed 4) 'big (hasheq)))
    (hasheq)))

(describe "Padding on new IR"
  (it "round-trips"
    (define v (hasheq 'tag #xAA 'val #xDEADBEEF))
    (define bs (ir-encode padded-protocol v))
    (check-equal? (bytes-length bs) 8)
    (check-equal? (bytes-ref bs 0) #xAA)
    (check-equal? (subbytes bs 1 4) (bytes 0 0 0))
    (check-equal? (ir-decode padded-protocol bs) v)))

;; ============================================================
;; Little-endian
;; ============================================================

(define le-protocol
  (wire-protocol 'le
    (list (wire-field 'val 'uint (width-fixed 4) 'little (hasheq)))
    (hasheq)))

(describe "Little-endian on new IR"
  (it "encodes LE"
    (define bs (ir-encode le-protocol (hasheq 'val #x01020304)))
    (check-equal? bs (bytes #x04 #x03 #x02 #x01)))

  (it "round-trips"
    (define v (hasheq 'val #xDEADBEEF))
    (check-equal? (ir-decode le-protocol (ir-encode le-protocol v)) v)))

;; ============================================================
;; Conditional presence
;; ============================================================

(define conditional-protocol
  (wire-protocol 'conditional
    (list (wire-field 'flags 'uint (width-fixed 1) 'big (hasheq))
          (wire-field 'opt   'uint (width-fixed 2) 'big
            (hasheq 'present-when (λ (lk) (> (lk 'flags) 0))))
          (wire-field 'tail  'uint (width-fixed 1) 'big (hasheq)))
    (hasheq)))

(describe "Conditional presence on new IR"
  (it "encodes with field present"
    (define bs (ir-encode conditional-protocol (hasheq 'flags 1 'opt #xABCD 'tail #xFF)))
    (check-equal? bs (bytes 1 #xAB #xCD #xFF)))

  (it "encodes with field absent"
    (define bs (ir-encode conditional-protocol (hasheq 'flags 0 'opt 0 'tail #xFF)))
    (check-equal? bs (bytes 0 #xFF)))

  (it "decodes with field present"
    (define h (ir-decode conditional-protocol (bytes 1 #xAB #xCD #xFF)))
    (check-equal? (hash-ref h 'opt) #xABCD)
    (check-equal? (hash-ref h 'tail) #xFF))

  (it "decodes with field absent"
    (define h (ir-decode conditional-protocol (bytes 0 #xFF)))
    (check-equal? (hash-ref h 'opt) #f)
    (check-equal? (hash-ref h 'tail) #xFF)))
