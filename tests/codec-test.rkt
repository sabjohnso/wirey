#lang racket/base

(require rackunit
         rackunit/spec
         wirey/field
         wirey/protocol
         wirey/codec
         wirey/length-expr)

;; -- helpers --
(define (hex->bytes str)
  (define clean (regexp-replace* #rx" " str ""))
  (apply bytes
         (for/list ([i (in-range 0 (string-length clean) 2)])
           (string->number (substring clean i (+ i 2)) 16))))

;; ===== Encoding =====

(describe "encode"
  (context "uint fields"
    (it "encodes a 2-byte big-endian uint"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'uint 2 'big))))
      (check-equal? (encode p (hasheq 'val #x0102))
                    (bytes 1 2)))

    (it "encodes a 2-byte little-endian uint"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'uint 2 'little))))
      (check-equal? (encode p (hasheq 'val #x0102))
                    (bytes 2 1)))

    (it "encodes a 4-byte big-endian uint"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'uint 4 'big))))
      (check-equal? (encode p (hasheq 'val #xDEADBEEF))
                    (hex->bytes "DE AD BE EF")))

    (it "encodes a 6-byte big-endian uint (ITCH timestamp)"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'ts 'uint 6 'big))))
      (check-equal? (encode p (hasheq 'ts #x0102030405FF))
                    (hex->bytes "01 02 03 04 05 FF")))

    (it "encodes a 1-byte uint"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'v 'uint 1 'big))))
      (check-equal? (encode p (hasheq 'v #x42))
                    (bytes #x42)))

    (it "encodes an 8-byte big-endian uint"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'v 'uint 8 'big))))
      (check-equal? (encode p (hasheq 'v #x0102030405060708))
                    (hex->bytes "01 02 03 04 05 06 07 08"))))

  (context "sint fields"
    (it "encodes a positive sint as unsigned"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'sint 4 'big))))
      (check-equal? (encode p (hasheq 'val 1))
                    (hex->bytes "00 00 00 01")))

    (it "encodes a negative sint via two's complement"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'sint 4 'big))))
      (check-equal? (encode p (hasheq 'val -1))
                    (hex->bytes "FF FF FF FF")))

    (it "encodes a negative sint little-endian"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'sint 2 'little))))
      (check-equal? (encode p (hasheq 'val -2))
                    (bytes #xFE #xFF))))

  (context "alpha fields"
    (it "encodes a string right-padded with spaces"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'sym 'alpha 8 'big))))
      (check-equal? (encode p (hasheq 'sym "AAPL"))
                    (bytes-append #"AAPL" #"    ")))

    (it "encodes a single-char alpha"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'c 'alpha 1 'big))))
      (check-equal? (encode p (hasheq 'c "S"))
                    #"S"))

    (it "truncates string to field width"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'c 'alpha 2 'big))))
      (check-equal? (encode p (hasheq 'c "ABCD"))
                    #"AB")))

  (context "octets fields"
    (it "copies raw bytes"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'mac 'octets 6 'big))))
      (check-equal? (encode p (hasheq 'mac (bytes 1 2 3 4 5 6)))
                    (bytes 1 2 3 4 5 6))))

  (context "multi-field protocol"
    (it "encodes ITCH system event message"
      (define p (make-protocol-desc 'system-event
                  (list (make-field-desc 'message-type 'alpha 1 'big)
                        (make-field-desc 'stock-locate 'uint  2 'big)
                        (make-field-desc 'tracking     'uint  2 'big)
                        (make-field-desc 'timestamp    'uint  6 'big)
                        (make-field-desc 'event-code   'alpha 1 'big))))
      (check-equal?
       (encode p (hasheq 'message-type "S"
                         'stock-locate 0
                         'tracking     0
                         'timestamp    #x00000E4E1C00  ; some timestamp
                         'event-code   "O"))
       (bytes-append #"S"
                     (bytes 0 0)
                     (bytes 0 0)
                     (hex->bytes "00 00 0E 4E 1C 00")
                     #"O")))))

;; ===== Decoding =====

(describe "decode"
  (context "uint fields"
    (it "decodes a 2-byte big-endian uint"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'uint 2 'big))))
      (check-equal? (hash-ref (decode p (bytes 1 2)) 'val)
                    #x0102))

    (it "decodes a 2-byte little-endian uint"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'uint 2 'little))))
      (check-equal? (hash-ref (decode p (bytes 2 1)) 'val)
                    #x0102))

    (it "decodes a 6-byte big-endian uint"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'ts 'uint 6 'big))))
      (check-equal? (hash-ref (decode p (hex->bytes "01 02 03 04 05 FF")) 'ts)
                    #x0102030405FF))

    (it "decodes with an offset"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'uint 2 'big))))
      (check-equal? (hash-ref (decode p (bytes 0 0 1 2) #:offset 2) 'val)
                    #x0102)))

  (context "sint fields"
    (it "decodes a positive sint"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'sint 4 'big))))
      (check-equal? (hash-ref (decode p (hex->bytes "00 00 00 01")) 'val)
                    1))

    (it "decodes a negative sint"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'sint 4 'big))))
      (check-equal? (hash-ref (decode p (hex->bytes "FF FF FF FF")) 'val)
                    -1)))

  (context "alpha fields"
    (it "decodes and trims trailing spaces"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'sym 'alpha 8 'big))))
      (check-equal? (hash-ref (decode p (bytes-append #"AAPL" #"    ")) 'sym)
                    "AAPL"))

    (it "decodes a full-width alpha without trimming"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'sym 'alpha 4 'big))))
      (check-equal? (hash-ref (decode p #"MSFT") 'sym)
                    "MSFT")))

  (context "octets fields"
    (it "decodes raw bytes"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'mac 'octets 6 'big))))
      (check-equal? (hash-ref (decode p (bytes 1 2 3 4 5 6)) 'mac)
                    (bytes 1 2 3 4 5 6))))

  (context "round-trip"
    (it "decode(encode(v)) = v for uint"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'val 'uint 4 'big))))
      (define v (hasheq 'val #xCAFEBABE))
      (check-equal? (decode p (encode p v)) v))

    (it "decode(encode(v)) = v for multi-field ITCH message"
      (define p (make-protocol-desc 'system-event
                  (list (make-field-desc 'message-type 'alpha 1 'big)
                        (make-field-desc 'stock-locate 'uint  2 'big)
                        (make-field-desc 'tracking     'uint  2 'big)
                        (make-field-desc 'timestamp    'uint  6 'big)
                        (make-field-desc 'event-code   'alpha 1 'big))))
      (define v (hasheq 'message-type "S"
                        'stock-locate 0
                        'tracking     42
                        'timestamp    #x00000E4E1C00
                        'event-code   "O"))
      (check-equal? (decode p (encode p v)) v))))

;; ===== Bitfield Encoding =====

(describe "encode (bitfields)"
  (context "two 4-bit nibbles in one byte"
    (it "encodes version=4, ihl=5 as 0x45"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'version 'uint 4 'big #:unit 'bits)
                        (make-field-desc 'ihl     'uint 4 'big #:unit 'bits))))
      (check-equal? (encode p (hasheq 'version 4 'ihl 5))
                    (bytes #x45))))

  (context "3+13 bit split across two bytes"
    (it "encodes flags=2, fragment-offset=0 as 0x4000"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'flags   'uint 3  'big #:unit 'bits)
                        (make-field-desc 'frag-off 'uint 13 'big #:unit 'bits))))
      ;; flags=2 → 010, frag-off=0 → 0000000000000 → 0100_0000_0000_0000 = 0x4000
      (check-equal? (encode p (hasheq 'flags 2 'frag-off 0))
                    (bytes #x40 #x00))))

  (context "6+2 bit split"
    (it "encodes dscp=0, ecn=3 as 0x03"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'dscp 'uint 6 'big #:unit 'bits)
                        (make-field-desc 'ecn  'uint 2 'big #:unit 'bits))))
      ;; dscp=0 → 000000, ecn=3 → 11 → 00000011 = 0x03
      (check-equal? (encode p (hasheq 'dscp 0 'ecn 3))
                    (bytes #x03))))

  (context "mixed byte and bitfields"
    (it "encodes bitfield group followed by byte field"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'version 'uint 4  'big #:unit 'bits)
                        (make-field-desc 'ihl     'uint 4  'big #:unit 'bits)
                        (make-field-desc 'total   'uint 2  'big))))
      (check-equal? (encode p (hasheq 'version 4 'ihl 5 'total 1500))
                    (bytes #x45 #x05 #xDC))))

  (context "byte field between two bitfield groups"
    (it "encodes correctly"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'a 'uint 4 'big #:unit 'bits)
                        (make-field-desc 'b 'uint 4 'big #:unit 'bits)
                        (make-field-desc 'c 'uint 2 'big)
                        (make-field-desc 'd 'uint 3 'big #:unit 'bits)
                        (make-field-desc 'e 'uint 13 'big #:unit 'bits))))
      ;; a=0xF, b=0x0 → 0xF0
      ;; c=0x0102
      ;; d=7, e=0 → 111_0000000000000 = 0xE000
      (check-equal? (encode p (hasheq 'a #xF 'b 0 'c #x0102 'd 7 'e 0))
                    (bytes #xF0 #x01 #x02 #xE0 #x00)))))

;; ===== Bitfield Decoding =====

(describe "decode (bitfields)"
  (context "two 4-bit nibbles"
    (it "decodes 0x45 as version=4, ihl=5"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'version 'uint 4 'big #:unit 'bits)
                        (make-field-desc 'ihl     'uint 4 'big #:unit 'bits))))
      (define v (decode p (bytes #x45)))
      (check-equal? (hash-ref v 'version) 4)
      (check-equal? (hash-ref v 'ihl) 5)))

  (context "3+13 bit split"
    (it "decodes 0x4000 as flags=2, frag-off=0"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'flags   'uint 3  'big #:unit 'bits)
                        (make-field-desc 'frag-off 'uint 13 'big #:unit 'bits))))
      (define v (decode p (bytes #x40 #x00)))
      (check-equal? (hash-ref v 'flags) 2)
      (check-equal? (hash-ref v 'frag-off) 0)))

  (context "6+2 bit split"
    (it "decodes 0x03 as dscp=0, ecn=3"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'dscp 'uint 6 'big #:unit 'bits)
                        (make-field-desc 'ecn  'uint 2 'big #:unit 'bits))))
      (define v (decode p (bytes #x03)))
      (check-equal? (hash-ref v 'dscp) 0)
      (check-equal? (hash-ref v 'ecn) 3)))

  (context "mixed byte and bitfields"
    (it "decodes bitfield group followed by byte field"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'version 'uint 4  'big #:unit 'bits)
                        (make-field-desc 'ihl     'uint 4  'big #:unit 'bits)
                        (make-field-desc 'total   'uint 2  'big))))
      (define v (decode p (bytes #x45 #x05 #xDC)))
      (check-equal? (hash-ref v 'version) 4)
      (check-equal? (hash-ref v 'ihl) 5)
      (check-equal? (hash-ref v 'total) 1500)))

  (context "round-trip"
    (it "decode(encode(v)) = v for bitfields"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'version 'uint 4  'big #:unit 'bits)
                        (make-field-desc 'ihl     'uint 4  'big #:unit 'bits)
                        (make-field-desc 'total   'uint 2  'big))))
      (define v (hasheq 'version 4 'ihl 5 'total 1500))
      (check-equal? (decode p (encode p v)) v))

    (it "decode(encode(v)) = v for IPv4-like byte 0-1 and 6-7"
      (define p (make-protocol-desc 'ipv4-partial
                  (list (make-field-desc 'version 'uint 4  'big #:unit 'bits)
                        (make-field-desc 'ihl     'uint 4  'big #:unit 'bits)
                        (make-field-desc 'dscp    'uint 6  'big #:unit 'bits)
                        (make-field-desc 'ecn     'uint 2  'big #:unit 'bits)
                        (make-field-desc 'total   'uint 2  'big)
                        (make-field-desc 'ident   'uint 2  'big)
                        (make-field-desc 'flags   'uint 3  'big #:unit 'bits)
                        (make-field-desc 'frag    'uint 13 'big #:unit 'bits))))
      (define v (hasheq 'version 4 'ihl 5
                        'dscp 0 'ecn 0
                        'total 1500
                        'ident #xABCD
                        'flags 2 'frag 0))
      (check-equal? (decode p (encode p v)) v))))

;; ===== LSB Bit Ordering =====

(describe "encode (LSB bitfields)"
  (context "two 4-bit nibbles LSB-first"
    (it "encodes a=0xF, b=0x0 as 0x0F (a in low bits)"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'a 'uint 4 'big #:unit 'bits #:bit-order 'lsb)
                        (make-field-desc 'b 'uint 4 'big #:unit 'bits #:bit-order 'lsb))))
      ;; LSB-first: a occupies bits 0-3, b occupies bits 4-7
      ;; a=0xF → bits 0-3 = 1111, b=0x0 → bits 4-7 = 0000 → byte = 0x0F
      (check-equal? (encode p (hasheq 'a #xF 'b 0))
                    (bytes #x0F))))

  (context "3+5 bit LSB split"
    (it "encodes flags=7, value=0 as 0x07"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'flags 'uint 3 'big #:unit 'bits #:bit-order 'lsb)
                        (make-field-desc 'value 'uint 5 'big #:unit 'bits #:bit-order 'lsb))))
      ;; LSB: flags in bits 0-2 = 111, value in bits 3-7 = 00000 → 0x07
      (check-equal? (encode p (hasheq 'flags 7 'value 0))
                    (bytes #x07))))

  (context "mixed MSB and LSB groups"
    (it "encodes MSB group then LSB group correctly"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'msb-hi 'uint 4 'big #:unit 'bits)
                        (make-field-desc 'msb-lo 'uint 4 'big #:unit 'bits)
                        (make-field-desc 'lsb-a  'uint 4 'big #:unit 'bits #:bit-order 'lsb)
                        (make-field-desc 'lsb-b  'uint 4 'big #:unit 'bits #:bit-order 'lsb))))
      ;; MSB group: hi=0xA, lo=0x5 → 0xA5
      ;; LSB group: a=0xF, b=0x0 → 0x0F
      (check-equal? (encode p (hasheq 'msb-hi #xA 'msb-lo #x5
                                      'lsb-a #xF 'lsb-b #x0))
                    (bytes #xA5 #x0F)))))

(describe "decode (LSB bitfields)"
  (context "two 4-bit nibbles LSB-first"
    (it "decodes 0x0F as a=0xF, b=0x0"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'a 'uint 4 'big #:unit 'bits #:bit-order 'lsb)
                        (make-field-desc 'b 'uint 4 'big #:unit 'bits #:bit-order 'lsb))))
      (define v (decode p (bytes #x0F)))
      (check-equal? (hash-ref v 'a) #xF)
      (check-equal? (hash-ref v 'b) 0)))

  (context "round-trip"
    (it "decode(encode(v)) = v for LSB bitfields"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'a 'uint 4 'big #:unit 'bits #:bit-order 'lsb)
                        (make-field-desc 'b 'uint 4 'big #:unit 'bits #:bit-order 'lsb))))
      (define v (hasheq 'a 3 'b 12))
      (check-equal? (decode p (encode p v)) v))

    (it "decode(encode(v)) = v for LSB 3+5 split"
      (define p (make-protocol-desc 'test
                  (list (make-field-desc 'flags 'uint 3 'big #:unit 'bits #:bit-order 'lsb)
                        (make-field-desc 'value 'uint 5 'big #:unit 'bits #:bit-order 'lsb))))
      (define v (hasheq 'flags 5 'value 19))
      (check-equal? (decode p (encode p v)) v))))

;; ===== Variable-Length Encoding =====

(describe "encode (variable-length)"
  (context "field-ref width"
    (it "encodes a variable-length field using referenced field's value"
      (define p (make-protocol-desc 'pkt
                  (list (make-field-desc 'len  'uint   2 'big)
                        (make-field-desc 'data 'octets (make-field-ref 'len) 'big))))
      (define bs (encode p (hasheq 'len 3 'data (bytes 1 2 3))))
      ;; 2 bytes for len (big-endian 3) + 3 bytes of data
      (check-equal? bs (bytes 0 3 1 2 3)))

    (it "validates data length matches the length field"
      (define p (make-protocol-desc 'pkt
                  (list (make-field-desc 'len  'uint   2 'big)
                        (make-field-desc 'data 'octets (make-field-ref 'len) 'big))))
      (check-exn exn:fail?
        (λ () (encode p (hasheq 'len 3 'data (bytes 1 2)))))))

  (context "compute width"
    (it "encodes with a computed width expression"
      (define p (make-protocol-desc 'msg
                  (list (make-field-desc 'hdr-len 'uint 1 'big)
                        (make-field-desc 'payload 'octets
                                         (make-compute '(- (field-ref hdr-len) 1)
                                                       (λ (lk) (- (lk 'hdr-len) 1)))
                                         'big))))
      ;; hdr-len=5 means payload is 4 bytes
      (define bs (encode p (hasheq 'hdr-len 5 'payload (bytes 10 20 30 40))))
      (check-equal? bs (bytes 5 10 20 30 40))))

  (context "mixed fixed and variable fields"
    (it "encodes fixed fields before and after variable field"
      (define p (make-protocol-desc 'framed
                  (list (make-field-desc 'tag  'uint   1 'big)
                        (make-field-desc 'len  'uint   2 'big)
                        (make-field-desc 'data 'octets (make-field-ref 'len) 'big)
                        (make-field-desc 'crc  'uint   2 'big))))
      (define bs (encode p (hasheq 'tag #xAA 'len 2 'data (bytes #xBB #xCC) 'crc #xDDEE)))
      (check-equal? bs (bytes #xAA #x00 #x02 #xBB #xCC #xDD #xEE)))))

;; ===== Variable-Length Decoding =====

(describe "decode (variable-length)"
  (context "field-ref width"
    (it "decodes a variable-length field"
      (define p (make-protocol-desc 'pkt
                  (list (make-field-desc 'len  'uint   2 'big)
                        (make-field-desc 'data 'octets (make-field-ref 'len) 'big))))
      (define v (decode p (bytes 0 3 1 2 3)))
      (check-equal? (hash-ref v 'len) 3)
      (check-equal? (hash-ref v 'data) (bytes 1 2 3))))

  (context "mixed fixed and variable fields"
    (it "decodes fields after the variable field correctly"
      (define p (make-protocol-desc 'framed
                  (list (make-field-desc 'tag  'uint   1 'big)
                        (make-field-desc 'len  'uint   2 'big)
                        (make-field-desc 'data 'octets (make-field-ref 'len) 'big)
                        (make-field-desc 'crc  'uint   2 'big))))
      (define v (decode p (bytes #xAA #x00 #x02 #xBB #xCC #xDD #xEE)))
      (check-equal? (hash-ref v 'tag) #xAA)
      (check-equal? (hash-ref v 'len) 2)
      (check-equal? (hash-ref v 'data) (bytes #xBB #xCC))
      (check-equal? (hash-ref v 'crc) #xDDEE)))

  (context "round-trip"
    (it "decode(encode(v)) = v for variable-length protocol"
      (define p (make-protocol-desc 'pkt
                  (list (make-field-desc 'len  'uint   2 'big)
                        (make-field-desc 'data 'octets (make-field-ref 'len) 'big))))
      (define v (hasheq 'len 4 'data (bytes 10 20 30 40)))
      (check-equal? (decode p (encode p v)) v))

    (it "decode(encode(v)) = v for framed message"
      (define p (make-protocol-desc 'framed
                  (list (make-field-desc 'tag  'uint   1 'big)
                        (make-field-desc 'len  'uint   2 'big)
                        (make-field-desc 'data 'octets (make-field-ref 'len) 'big)
                        (make-field-desc 'crc  'uint   2 'big))))
      (define v (hasheq 'tag #xAA 'len 5 'data (bytes 1 2 3 4 5) 'crc #x1234))
      (check-equal? (decode p (encode p v)) v))))

;; ===== Computed Fields Encoding =====

(describe "encode (computed fields)"
  (it "computes a field value via two-pass encoding"
    ;; Simple checksum: sum of all other bytes mod 256
    (define (simple-checksum buf)
      (define total 0)
      (for ([i (in-range (bytes-length buf))])
        (set! total (+ total (bytes-ref buf i))))
      (modulo total 256))
    (define p (make-protocol-desc 'msg
                (list (make-field-desc 'tag  'uint 1 'big)
                      (make-field-desc 'data 'uint 2 'big)
                      (make-field-desc 'chk  'uint 1 'big #:compute simple-checksum))))
    ;; Encode without providing 'chk — it should be computed
    (define bs (encode p (hasheq 'tag #xAA 'data #x0102)))
    ;; chk = (#xAA + #x01 + #x02 + 0) mod 256 = #xAD
    (check-equal? (bytes-ref bs 3) #xAD)
    ;; The other fields should be correct
    (check-equal? (bytes-ref bs 0) #xAA)
    (check-equal? (subbytes bs 1 3) (bytes #x01 #x02)))

  (it "ignores a provided value for computed fields"
    (define (always-42 buf) 42)
    (define p (make-protocol-desc 'msg
                (list (make-field-desc 'val 'uint 1 'big)
                      (make-field-desc 'chk 'uint 1 'big #:compute always-42))))
    (define bs (encode p (hasheq 'val 99 'chk 0)))
    (check-equal? (bytes-ref bs 1) 42)))

;; ===== Contract Validation on Encode =====

(describe "encode (contract validation)"
  (it "passes when contract is satisfied"
    (define (port? v) (and (integer? v) (<= 0 v 65535)))
    (define p (make-protocol-desc 'msg
                (list (make-field-desc 'port 'uint 2 'big #:contract port?))))
    (check-not-exn (λ () (encode p (hasheq 'port 80)))))

  (it "raises when contract is violated"
    (define (port? v) (and (integer? v) (<= 0 v 65535)))
    (define p (make-protocol-desc 'msg
                (list (make-field-desc 'port 'uint 2 'big #:contract port?))))
    (check-exn exn:fail?
      (λ () (encode p (hasheq 'port 70000)))))

  (it "includes field name in error message"
    (define (positive? v) (> v 0))
    (define p (make-protocol-desc 'msg
                (list (make-field-desc 'count 'uint 1 'big #:contract positive?))))
    (check-exn #rx"count"
      (λ () (encode p (hasheq 'count 0)))))

  (it "skips contract check for computed fields"
    (define (always-valid? v) #f) ;; would fail if checked
    (define p (make-protocol-desc 'msg
                (list (make-field-desc 'val 'uint 1 'big)
                      (make-field-desc 'chk 'uint 1 'big
                                       #:compute (λ (buf) 42)
                                       #:contract always-valid?))))
    ;; Should not raise — computed fields aren't checked at encode time
    (check-not-exn (λ () (encode p (hasheq 'val 1))))))

;; ===== String Encodings =====

(describe "encode/decode utf8"
  (it "encodes ASCII string null-padded"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'name 'utf8 8 'big))))
    (define bs (encode p (hasheq 'name "hello")))
    (check-equal? bs (bytes-append #"hello" (bytes 0 0 0))))

  (it "decodes trimming null padding"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'name 'utf8 8 'big))))
    (check-equal? (hash-ref (decode p (bytes-append #"hello" (bytes 0 0 0))) 'name)
                  "hello"))

  (it "round-trips multi-byte characters"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'name 'utf8 12 'big))))
    ;; "café" = 5 bytes in UTF-8 (é = 2 bytes)
    (define v (hasheq 'name "café"))
    (check-equal? (hash-ref (decode p (encode p v)) 'name) "café")))

(describe "encode/decode utf16"
  (it "encodes big-endian UTF-16"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'name 'utf16 8 'big))))
    ;; "AB" = 0x0041 0x0042 in UTF-16BE, then null-padded
    (define bs (encode p (hasheq 'name "AB")))
    (check-equal? (subbytes bs 0 4) (bytes #x00 #x41 #x00 #x42)))

  (it "decodes big-endian UTF-16"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'name 'utf16 8 'big))))
    (define bs (bytes #x00 #x41 #x00 #x42 #x00 #x00 #x00 #x00))
    (check-equal? (hash-ref (decode p bs) 'name) "AB"))

  (it "round-trips"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'name 'utf16 10 'big))))
    (define v (hasheq 'name "Test"))
    (check-equal? (hash-ref (decode p (encode p v)) 'name) "Test")))

(describe "encode/decode utf32"
  (it "encodes big-endian UTF-32"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'name 'utf32 12 'big))))
    ;; "AB" = 0x00000041 0x00000042 in UTF-32BE, then null-padded
    (define bs (encode p (hasheq 'name "AB")))
    (check-equal? (subbytes bs 0 8)
                  (bytes #x00 #x00 #x00 #x41 #x00 #x00 #x00 #x42)))

  (it "round-trips"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'name 'utf32 16 'big))))
    (define v (hasheq 'name "Test"))
    (check-equal? (hash-ref (decode p (encode p v)) 'name) "Test")))

(describe "encode/decode with #:terminator"
  (it "encodes null-terminated alpha string"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'name 'alpha 8 'big #:terminator 0))))
    (define bs (encode p (hasheq 'name "hello")))
    ;; "hello" + null + padding zeros
    (check-equal? (bytes-ref bs 5) 0)
    (check-equal? (bytes-length bs) 8))

  (it "decodes up to null terminator"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'name 'alpha 8 'big #:terminator 0))))
    (define bs (bytes-append #"hello" (bytes 0 0 0)))
    (check-equal? (hash-ref (decode p bs) 'name) "hello"))

  (it "decodes full-width string with no null"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'name 'alpha 5 'big #:terminator 0))))
    (check-equal? (hash-ref (decode p #"hello") 'name) "hello"))

  (it "works with utf8 #:terminator"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'name 'utf8 8 'big #:terminator 0))))
    (define bs (bytes-append (string->bytes/utf-8 "hi") (bytes 0 0 0 0 0 0)))
    (check-equal? (hash-ref (decode p bs) 'name) "hi"))

  (it "works with utf16 #:terminator"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'name 'utf16 8 'big #:terminator 0))))
    ;; "AB" in UTF-16BE = 00 41 00 42, then null terminated
    (define bs (bytes #x00 #x41 #x00 #x42 #x00 #x00 #x00 #x00))
    (check-equal? (hash-ref (decode p bs) 'name) "AB")))

;; ===== New Field Types =====

(describe "encode/decode float32"
  (it "encodes and decodes 1.0 big-endian"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'val 'float32 4 'big))))
    (define bs (encode p (hasheq 'val 1.0)))
    ;; IEEE 754: 1.0 = 3F800000
    (check-equal? bs (bytes #x3F #x80 #x00 #x00))
    (define v (decode p bs))
    (check-equal? (hash-ref v 'val) 1.0))

  (it "encodes and decodes -0.5 little-endian"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'val 'float32 4 'little))))
    (define bs (encode p (hasheq 'val -0.5)))
    (define v (decode p bs))
    (check-= (hash-ref v 'val) -0.5 1e-7))

  (it "round-trips various values"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'val 'float32 4 'big))))
    (for ([x (list 0.0 1.0 -1.0 3.14 1e10 1e-10)])
      (check-= (hash-ref (decode p (encode p (hasheq 'val x))) 'val) x
               (* (abs x) 1e-6)))))

(describe "encode/decode float64"
  (it "encodes and decodes 1.0 big-endian"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'val 'float64 8 'big))))
    (define bs (encode p (hasheq 'val 1.0)))
    (check-equal? bs (bytes #x3F #xF0 #x00 #x00 #x00 #x00 #x00 #x00))
    (check-equal? (hash-ref (decode p bs) 'val) 1.0))

  (it "round-trips pi"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'val 'float64 8 'big))))
    (define v (hasheq 'val 3.141592653589793))
    (check-equal? (decode p (encode p v)) v)))

(describe "encode/decode bool"
  (it "encodes #t as 1, #f as 0"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'flag 'bool 1 'big))))
    (check-equal? (encode p (hasheq 'flag #t)) (bytes 1))
    (check-equal? (encode p (hasheq 'flag #f)) (bytes 0)))

  (it "decodes 0 as #f, nonzero as #t"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'flag 'bool 1 'big))))
    (check-equal? (hash-ref (decode p (bytes 0)) 'flag) #f)
    (check-equal? (hash-ref (decode p (bytes 1)) 'flag) #t)
    (check-equal? (hash-ref (decode p (bytes #xFF)) 'flag) #t)))

(describe "encode/decode bcd"
  (it "encodes 1234 as packed BCD in 2 bytes"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'val 'bcd 2 'big))))
    ;; 1234 → 12 34 (two bytes, two digits per byte)
    (check-equal? (encode p (hasheq 'val 1234)) (bytes #x12 #x34)))

  (it "decodes packed BCD bytes to integer"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'val 'bcd 2 'big))))
    (check-equal? (hash-ref (decode p (bytes #x12 #x34)) 'val) 1234))

  (it "round-trips"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'val 'bcd 3 'big))))
    (define v (hasheq 'val 123456))
    (check-equal? (decode p (encode p v)) v))

  (it "zero-pads small values"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'val 'bcd 2 'big))))
    ;; 42 → 00 42
    (check-equal? (encode p (hasheq 'val 42)) (bytes #x00 #x42))))

;; ===== Repetition / Arrays =====

(describe "encode/decode repeat (fixed count)"
  (it "encodes a fixed array of uint16"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'vals 'uint 2 'big #:repeat 3))))
    (define bs (encode p (hasheq 'vals (list #x0001 #x0002 #x0003))))
    (check-equal? bs (bytes #x00 #x01 #x00 #x02 #x00 #x03)))

  (it "decodes a fixed array of uint16"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'vals 'uint 2 'big #:repeat 3))))
    (define v (decode p (bytes #x00 #x01 #x00 #x02 #x00 #x03)))
    (check-equal? (hash-ref v 'vals) (list #x0001 #x0002 #x0003)))

  (it "round-trips"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'vals 'uint 4 'big #:repeat 2))))
    (define v (hasheq 'vals (list #xDEADBEEF #xCAFEBABE)))
    (check-equal? (decode p (encode p v)) v)))

(describe "encode/decode repeat (count from field)"
  (it "encodes with count-prefixed array"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'count 'uint 1 'big)
                      (make-field-desc 'items 'uint 2 'big
                                       #:repeat (make-field-ref 'count)))))
    (define bs (encode p (hasheq 'count 2 'items (list #x000A #x000B))))
    (check-equal? bs (bytes 2 #x00 #x0A #x00 #x0B)))

  (it "decodes with count-prefixed array"
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'count 'uint 1 'big)
                      (make-field-desc 'items 'uint 2 'big
                                       #:repeat (make-field-ref 'count)))))
    (define v (decode p (bytes 3 #x00 #x01 #x00 #x02 #x00 #x03)))
    (check-equal? (hash-ref v 'count) 3)
    (check-equal? (hash-ref v 'items) (list 1 2 3))))

(describe "encode/decode repeat-until"
  (it "encodes elements followed by a sentinel"
    (define (sentinel? v) (= v 0))
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'items 'uint 2 'big
                                       #:repeat-until sentinel?))))
    (define bs (encode p (hasheq 'items (list #x0001 #x0002 #x0003))))
    ;; Encodes the items followed by a 0x0000 sentinel
    (check-equal? bs (bytes #x00 #x01 #x00 #x02 #x00 #x03 #x00 #x00)))

  (it "decodes until sentinel is found"
    (define (sentinel? v) (= v 0))
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'items 'uint 2 'big
                                       #:repeat-until sentinel?))))
    (define v (decode p (bytes #x00 #x01 #x00 #x02 #x00 #x00 #xFF #xFF)))
    (check-equal? (hash-ref v 'items) (list 1 2)))

  (it "handles fields after repeat-until"
    (define (sentinel? v) (= v 0))
    (define p (make-protocol-desc 'test
                (list (make-field-desc 'items 'uint 1 'big #:repeat-until sentinel?)
                      (make-field-desc 'tail  'uint 1 'big))))
    (define v (decode p (bytes 1 2 3 0 #xFF)))
    (check-equal? (hash-ref v 'items) (list 1 2 3))
    (check-equal? (hash-ref v 'tail) #xFF)))

;; ===== Padding and Alignment =====

(describe "encode (padding)"
  (it "encodes padding as zero bytes"
    (define p (make-protocol-desc 'msg
                (list (make-field-desc 'tag 'uint 1 'big)
                      (make-field-desc 'pad 'padding 3 'big)
                      (make-field-desc 'val 'uint 4 'big))))
    (define bs (encode p (hasheq 'tag #xAA 'val #xDEADBEEF)))
    (check-equal? bs (bytes #xAA #x00 #x00 #x00 #xDE #xAD #xBE #xEF)))

  (it "padding fields are not required in values hash"
    (define p (make-protocol-desc 'msg
                (list (make-field-desc 'tag 'uint 1 'big)
                      (make-field-desc 'pad 'padding 2 'big)
                      (make-field-desc 'val 'uint 1 'big))))
    (check-not-exn
     (λ () (encode p (hasheq 'tag 1 'val 2))))))

(describe "decode (padding)"
  (it "skips padding fields in decoded hash"
    (define p (make-protocol-desc 'msg
                (list (make-field-desc 'tag 'uint 1 'big)
                      (make-field-desc 'pad 'padding 3 'big)
                      (make-field-desc 'val 'uint 4 'big))))
    (define v (decode p (bytes #xAA #x00 #x00 #x00 #xDE #xAD #xBE #xEF)))
    (check-equal? (hash-ref v 'tag) #xAA)
    (check-equal? (hash-ref v 'val) #xDEADBEEF)
    (check-false (hash-has-key? v 'pad)))

  (it "correctly offsets fields after padding"
    (define p (make-protocol-desc 'msg
                (list (make-field-desc 'a 'uint 1 'big)
                      (make-field-desc 'pad 'padding 5 'big)
                      (make-field-desc 'b 'uint 2 'big))))
    (define v (decode p (bytes #x01 0 0 0 0 0 #x00 #x42)))
    (check-equal? (hash-ref v 'a) 1)
    (check-equal? (hash-ref v 'b) #x42)))

;; ===== Conditional Presence =====

(describe "encode (conditional fields)"
  (it "includes field when predicate is true"
    (define p (make-protocol-desc 'msg
                (list (make-field-desc 'flags 'uint 1 'big)
                      (make-field-desc 'extra 'uint 2 'big
                                       #:present-when (λ (lk) (> (lk 'flags) 0))))))
    (define bs (encode p (hasheq 'flags 1 'extra #x1234)))
    (check-equal? bs (bytes 1 #x12 #x34)))

  (it "excludes field when predicate is false"
    (define p (make-protocol-desc 'msg
                (list (make-field-desc 'flags 'uint 1 'big)
                      (make-field-desc 'extra 'uint 2 'big
                                       #:present-when (λ (lk) (> (lk 'flags) 0))))))
    (define bs (encode p (hasheq 'flags 0 'extra #x1234)))
    ;; extra is absent — only flags byte
    (check-equal? bs (bytes 0)))

  (it "handles fields after conditional correctly"
    (define p (make-protocol-desc 'msg
                (list (make-field-desc 'flags 'uint 1 'big)
                      (make-field-desc 'opt   'uint 2 'big
                                       #:present-when (λ (lk) (> (lk 'flags) 0)))
                      (make-field-desc 'tail  'uint 1 'big))))
    ;; With opt present
    (check-equal? (encode p (hasheq 'flags 1 'opt #xABCD 'tail #xFF))
                  (bytes 1 #xAB #xCD #xFF))
    ;; Without opt
    (check-equal? (encode p (hasheq 'flags 0 'opt 0 'tail #xFF))
                  (bytes 0 #xFF))))

(describe "decode (conditional fields)"
  (it "decodes field when predicate is true"
    (define p (make-protocol-desc 'msg
                (list (make-field-desc 'flags 'uint 1 'big)
                      (make-field-desc 'extra 'uint 2 'big
                                       #:present-when (λ (lk) (> (lk 'flags) 0))))))
    (define v (decode p (bytes 1 #x12 #x34)))
    (check-equal? (hash-ref v 'flags) 1)
    (check-equal? (hash-ref v 'extra) #x1234))

  (it "returns #f for absent field"
    (define p (make-protocol-desc 'msg
                (list (make-field-desc 'flags 'uint 1 'big)
                      (make-field-desc 'extra 'uint 2 'big
                                       #:present-when (λ (lk) (> (lk 'flags) 0))))))
    (define v (decode p (bytes 0)))
    (check-equal? (hash-ref v 'flags) 0)
    (check-equal? (hash-ref v 'extra) #f))

  (it "correctly offsets fields after absent conditional"
    (define p (make-protocol-desc 'msg
                (list (make-field-desc 'flags 'uint 1 'big)
                      (make-field-desc 'opt   'uint 2 'big
                                       #:present-when (λ (lk) (> (lk 'flags) 0)))
                      (make-field-desc 'tail  'uint 1 'big))))
    (define v (decode p (bytes 0 #xFF)))
    (check-equal? (hash-ref v 'flags) 0)
    (check-equal? (hash-ref v 'opt) #f)
    (check-equal? (hash-ref v 'tail) #xFF))

  (it "round-trips with conditional present"
    (define p (make-protocol-desc 'msg
                (list (make-field-desc 'flags 'uint 1 'big)
                      (make-field-desc 'opt   'uint 2 'big
                                       #:present-when (λ (lk) (> (lk 'flags) 0)))
                      (make-field-desc 'tail  'uint 1 'big))))
    (define v (hasheq 'flags 1 'opt #xABCD 'tail #xFF))
    (check-equal? (decode p (encode p v)) v)))

