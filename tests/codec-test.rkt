#lang racket/base

(require rackunit
         rackunit/spec
         wirey/field
         wirey/protocol
         wirey/codec)

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
