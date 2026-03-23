#lang racket/base

(require wirey/field
         wirey/protocol)

(provide encode
         decode)

;; ============================================================
;; Encoding: protocol-desc + hash → bytes
;; ============================================================

(define (encode pd values)
  (define fields (protocol-desc-fields pd))
  (define total (protocol-desc-total-size pd))
  (define buf (make-bytes total 0))
  (let loop ([fields fields] [offset 0])
    (unless (null? fields)
      (define f (car fields))
      (define name (field-desc-name f))
      (define width (field-desc-width f))
      (define val (hash-ref values name))
      (encode-field! buf offset f val)
      (loop (cdr fields) (+ offset width))))
  buf)

(define (encode-field! buf offset fd val)
  (define type (field-desc-type fd))
  (define width (field-desc-width fd))
  (define order (field-desc-byte-order fd))
  (case type
    [(uint)   (encode-uint! buf offset width order val)]
    [(sint)   (encode-sint! buf offset width order val)]
    [(alpha)  (encode-alpha! buf offset width val)]
    [(octets) (encode-octets! buf offset width val)]))

(define (encode-uint! buf offset width order val)
  (case order
    [(big)
     (for ([i (in-range (sub1 width) -1 -1)])
       (bytes-set! buf (+ offset (- (sub1 width) i))
                   (bitwise-and (arithmetic-shift val (* -8 i)) #xFF)))]
    [(little)
     (for ([i (in-range width)])
       (bytes-set! buf (+ offset i)
                   (bitwise-and (arithmetic-shift val (* -8 i)) #xFF)))]))

(define (encode-sint! buf offset width order val)
  (define unsigned (if (negative? val)
                       (+ val (expt 256 width))
                       val))
  (encode-uint! buf offset width order unsigned))

(define (encode-alpha! buf offset width val)
  (define src (string->bytes/latin-1 val))
  (define len (min (bytes-length src) width))
  (bytes-copy! buf offset src 0 len)
  ;; pad with spaces
  (for ([i (in-range len width)])
    (bytes-set! buf (+ offset i) (char->integer #\space))))

(define (encode-octets! buf offset width val)
  (bytes-copy! buf offset val 0 (min (bytes-length val) width)))

;; ============================================================
;; Decoding: protocol-desc + bytes + offset → hash
;; ============================================================

(define (decode pd data #:offset [start 0])
  (define fields (protocol-desc-fields pd))
  (let loop ([fields fields] [offset start] [result (hasheq)])
    (if (null? fields)
        result
        (let* ([f (car fields)]
               [width (field-desc-width f)]
               [name (field-desc-name f)]
               [val (decode-field data offset f)])
          (loop (cdr fields)
                (+ offset width)
                (hash-set result name val))))))

(define (decode-field data offset fd)
  (define type (field-desc-type fd))
  (define width (field-desc-width fd))
  (define order (field-desc-byte-order fd))
  (case type
    [(uint)   (decode-uint data offset width order)]
    [(sint)   (decode-sint data offset width order)]
    [(alpha)  (decode-alpha data offset width)]
    [(octets) (decode-octets data offset width)]))

(define (decode-uint data offset width order)
  (case order
    [(big)
     (for/fold ([acc 0]) ([i (in-range width)])
       (bitwise-ior (arithmetic-shift acc 8)
                    (bytes-ref data (+ offset i))))]
    [(little)
     (for/fold ([acc 0]) ([i (in-range (sub1 width) -1 -1)])
       (bitwise-ior (arithmetic-shift acc 8)
                    (bytes-ref data (+ offset i))))]))

(define (decode-sint data offset width order)
  (define unsigned (decode-uint data offset width order))
  (define sign-bit (expt 2 (sub1 (* 8 width))))
  (if (>= unsigned sign-bit)
      (- unsigned (expt 256 width))
      unsigned))

(define (decode-alpha data offset width)
  (define raw (subbytes data offset (+ offset width)))
  (string-trim-right (bytes->string/latin-1 raw)))

(define (decode-octets data offset width)
  (subbytes data offset (+ offset width)))

;; string-trim-right: remove trailing spaces
(define (string-trim-right s)
  (regexp-replace #rx" +$" s ""))
