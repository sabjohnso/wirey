#lang racket/base

;; ============================================================
;; CBOR (RFC 8949) — Concise Binary Object Representation
;;
;; Built on wirey primitives. CBOR is a recursive self-describing
;; format, so it uses wirey's codec functions directly rather than
;; a single struct/wire definition.
;; ============================================================

(require wirey/field
         wirey/codec)

(provide cbor-decode
         cbor-encode
         cbor-value?
         cbor-unsigned cbor-unsigned? cbor-unsigned-value
         cbor-negative cbor-negative? cbor-negative-value
         cbor-bytes cbor-bytes? cbor-bytes-value
         cbor-text cbor-text? cbor-text-value
         cbor-array cbor-array? cbor-array-items
         cbor-map cbor-map? cbor-map-entries
         cbor-tag cbor-tag? cbor-tag-number cbor-tag-content
         cbor-simple cbor-simple? cbor-simple-value
         cbor-float cbor-float? cbor-float-value
         cbor-true
         cbor-false
         cbor-null)

;; ============================================================
;; CBOR Value Representation
;; ============================================================

;; A CBOR value is one of:
(struct cbor-unsigned (value) #:transparent)        ;; major 0
(struct cbor-negative (value) #:transparent)        ;; major 1 (stored as positive: -1-n)
(struct cbor-bytes (value) #:transparent)           ;; major 2 (bytes)
(struct cbor-text (value) #:transparent)            ;; major 3 (string)
(struct cbor-array (items) #:transparent)           ;; major 4 (list of cbor values)
(struct cbor-map (entries) #:transparent)           ;; major 5 (list of (key . value) pairs)
(struct cbor-tag (number content) #:transparent)    ;; major 6
(struct cbor-simple (value) #:transparent)          ;; major 7 simple (0-255)
(struct cbor-float (value) #:transparent)           ;; major 7 float

(define cbor-true  (cbor-simple 21))
(define cbor-false (cbor-simple 20))
(define cbor-null  (cbor-simple 22))

(define (cbor-value? v)
  (or (cbor-unsigned? v) (cbor-negative? v)
      (cbor-bytes? v) (cbor-text? v)
      (cbor-array? v) (cbor-map? v)
      (cbor-tag? v) (cbor-simple? v) (cbor-float? v)))

;; ============================================================
;; Decoding
;; ============================================================

;; Decode one CBOR data item from data at offset.
;; Returns (values cbor-value next-offset)
(define (cbor-decode-item data offset)
  (define initial-byte (bytes-ref data offset))
  (define major (arithmetic-shift initial-byte -5))
  (define additional (bitwise-and initial-byte #x1F))

  ;; Decode the argument (unsigned integer) from additional-info
  (define-values (argument arg-end)
    (cond
      [(<= additional 23)
       (values additional (add1 offset))]
      [(= additional 24)
       (values (bytes-ref data (+ offset 1))
               (+ offset 2))]
      [(= additional 25)
       (values (decode-uint-be data (+ offset 1) 2)
               (+ offset 3))]
      [(= additional 26)
       (values (decode-uint-be data (+ offset 1) 4)
               (+ offset 5))]
      [(= additional 27)
       (values (decode-uint-be data (+ offset 1) 8)
               (+ offset 9))]
      [(= additional 31)
       ;; Indefinite length — argument is not used
       (values #f (add1 offset))]
      [else
       (error 'cbor-decode "reserved additional info value: ~a" additional)]))

  (case major
    ;; Major 0: unsigned integer
    [(0) (values (cbor-unsigned argument) arg-end)]

    ;; Major 1: negative integer (-1 - argument)
    [(1) (values (cbor-negative argument) arg-end)]

    ;; Major 2: byte string
    [(2)
     (if argument
         ;; Definite length
         (let ([payload (subbytes data arg-end (+ arg-end argument))])
           (values (cbor-bytes payload) (+ arg-end argument)))
         ;; Indefinite length: concatenate chunks until break
         (let loop ([off arg-end] [chunks '()])
           (if (= (bytes-ref data off) #xFF)
               (values (cbor-bytes (apply bytes-append (reverse chunks)))
                       (add1 off))
               (let-values ([(chunk next) (cbor-decode-item data off)])
                 (loop next (cons (cbor-bytes-value chunk) chunks))))))]

    ;; Major 3: text string (UTF-8)
    [(3)
     (if argument
         (let ([payload (subbytes data arg-end (+ arg-end argument))])
           (values (cbor-text (bytes->string/utf-8 payload)) (+ arg-end argument)))
         ;; Indefinite length
         (let loop ([off arg-end] [chunks '()])
           (if (= (bytes-ref data off) #xFF)
               (values (cbor-text (apply string-append (reverse chunks)))
                       (add1 off))
               (let-values ([(chunk next) (cbor-decode-item data off)])
                 (loop next (cons (cbor-text-value chunk) chunks))))))]

    ;; Major 4: array
    [(4)
     (if argument
         ;; Definite length
         (let loop ([n argument] [off arg-end] [items '()])
           (if (zero? n)
               (values (cbor-array (reverse items)) off)
               (let-values ([(item next) (cbor-decode-item data off)])
                 (loop (sub1 n) next (cons item items)))))
         ;; Indefinite length
         (let loop ([off arg-end] [items '()])
           (if (= (bytes-ref data off) #xFF)
               (values (cbor-array (reverse items)) (add1 off))
               (let-values ([(item next) (cbor-decode-item data off)])
                 (loop next (cons item items))))))]

    ;; Major 5: map
    [(5)
     (if argument
         ;; Definite length
         (let loop ([n argument] [off arg-end] [entries '()])
           (if (zero? n)
               (values (cbor-map (reverse entries)) off)
               (let-values ([(key k-end) (cbor-decode-item data off)])
                 (let-values ([(val v-end) (cbor-decode-item data k-end)])
                   (loop (sub1 n) v-end (cons (cons key val) entries))))))
         ;; Indefinite length
         (let loop ([off arg-end] [entries '()])
           (if (= (bytes-ref data off) #xFF)
               (values (cbor-map (reverse entries)) (add1 off))
               (let-values ([(key k-end) (cbor-decode-item data off)])
                 (let-values ([(val v-end) (cbor-decode-item data k-end)])
                   (loop v-end (cons (cons key val) entries)))))))]

    ;; Major 6: tag
    [(6)
     (let-values ([(content next) (cbor-decode-item data arg-end)])
       (values (cbor-tag argument content) next))]

    ;; Major 7: simple values and floats
    [(7)
     (cond
       ;; Simple values 0-23 (inline)
       [(<= additional 23)
        (values (cbor-simple additional) arg-end)]
       ;; Simple value in next byte
       [(= additional 24)
        (values (cbor-simple argument) arg-end)]
       ;; IEEE 754 half-precision (16-bit)
       [(= additional 25)
        (values (cbor-float (decode-float16 data (+ offset 1))) arg-end)]
       ;; IEEE 754 single-precision (32-bit)
       [(= additional 26)
        (values (cbor-float (floating-point-bytes->real
                             (subbytes data (+ offset 1) (+ offset 5)) #t))
                arg-end)]
       ;; IEEE 754 double-precision (64-bit)
       [(= additional 27)
        (values (cbor-float (floating-point-bytes->real
                             (subbytes data (+ offset 1) (+ offset 9)) #t))
                arg-end)]
       ;; Break (0xFF) — should not appear here as a standalone item
       [(= additional 31)
        (error 'cbor-decode "unexpected break code")]
       [else
        (error 'cbor-decode "reserved additional info in major 7: ~a" additional)])]

    [else (error 'cbor-decode "unknown major type: ~a" major)]))

;; Top-level decode: returns a cbor-value
(define (cbor-decode data #:offset [offset 0])
  (define-values (value _) (cbor-decode-item data offset))
  value)

;; ============================================================
;; Encoding
;; ============================================================

;; Encode a CBOR value to bytes
(define (cbor-encode val)
  (define out (open-output-bytes))
  (cbor-write val out)
  (get-output-bytes out))

(define (cbor-write val out)
  (cond
    [(cbor-unsigned? val) (write-head out 0 (cbor-unsigned-value val))]
    [(cbor-negative? val) (write-head out 1 (cbor-negative-value val))]
    [(cbor-bytes? val)
     (define bs (cbor-bytes-value val))
     (write-head out 2 (bytes-length bs))
     (write-bytes bs out)]
    [(cbor-text? val)
     (define bs (string->bytes/utf-8 (cbor-text-value val)))
     (write-head out 3 (bytes-length bs))
     (write-bytes bs out)]
    [(cbor-array? val)
     (define items (cbor-array-items val))
     (write-head out 4 (length items))
     (for ([item (in-list items)])
       (cbor-write item out))]
    [(cbor-map? val)
     (define entries (cbor-map-entries val))
     (write-head out 5 (length entries))
     (for ([entry (in-list entries)])
       (cbor-write (car entry) out)
       (cbor-write (cdr entry) out))]
    [(cbor-tag? val)
     (write-head out 6 (cbor-tag-number val))
     (cbor-write (cbor-tag-content val) out)]
    [(cbor-simple? val)
     (define sv (cbor-simple-value val))
     (if (<= sv 23)
         (write-byte (bitwise-ior (arithmetic-shift 7 5) sv) out)
         (begin
           (write-byte (bitwise-ior (arithmetic-shift 7 5) 24) out)
           (write-byte sv out)))]
    [(cbor-float? val)
     (define fv (cbor-float-value val))
     (define bs (real->floating-point-bytes fv 8 #t))
     (write-byte (bitwise-ior (arithmetic-shift 7 5) 27) out)
     (write-bytes bs out)]
    [else (error 'cbor-encode "not a CBOR value: ~e" val)]))

;; Write the initial byte + argument bytes for a given major type and argument
(define (write-head out major argument)
  (define base (arithmetic-shift major 5))
  (cond
    [(<= argument 23)
     (write-byte (bitwise-ior base argument) out)]
    [(<= argument #xFF)
     (write-byte (bitwise-ior base 24) out)
     (write-byte argument out)]
    [(<= argument #xFFFF)
     (write-byte (bitwise-ior base 25) out)
     (write-bytes (integer->bytes argument 2) out)]
    [(<= argument #xFFFFFFFF)
     (write-byte (bitwise-ior base 26) out)
     (write-bytes (integer->bytes argument 4) out)]
    [else
     (write-byte (bitwise-ior base 27) out)
     (write-bytes (integer->bytes argument 8) out)]))

;; ============================================================
;; Helpers
;; ============================================================

(define (decode-uint-be data offset width)
  (for/fold ([acc 0]) ([i (in-range width)])
    (bitwise-ior (arithmetic-shift acc 8)
                 (bytes-ref data (+ offset i)))))

(define (integer->bytes n width)
  (define bs (make-bytes width 0))
  (for ([i (in-range (sub1 width) -1 -1)])
    (bytes-set! bs (- (sub1 width) i)
                (bitwise-and (arithmetic-shift n (* -8 i)) #xFF)))
  bs)

;; Decode IEEE 754 half-precision float (16-bit)
(define (decode-float16 data offset)
  (define half (bitwise-ior (arithmetic-shift (bytes-ref data offset) 8)
                            (bytes-ref data (+ offset 1))))
  (define sign (arithmetic-shift half -15))
  (define exponent (bitwise-and (arithmetic-shift half -10) #x1F))
  (define mantissa (bitwise-and half #x3FF))
  (define value
    (cond
      [(= exponent 0)
       ;; Subnormal or zero
       (* (expt 2 -14) (/ mantissa 1024.0))]
      [(= exponent 31)
       ;; Infinity or NaN
       (if (zero? mantissa) +inf.0 +nan.0)]
      [else
       ;; Normal
       (* (expt 2 (- exponent 15)) (+ 1.0 (/ mantissa 1024.0)))]))
  (if (= sign 1) (- value) value))
