#lang racket/base

;; ============================================================
;; wirey IR Codec
;;
;; Encodes and decodes by walking the protocol element tree.
;; One function for each direction. No special cases — each
;; element type is handled by pattern matching.
;; ============================================================

(require wirey/ir)

(provide ir-encode
         ir-decode)

;; ============================================================
;; Decode: bytes + offset → field-value hash
;; ============================================================

(define (ir-decode proto data #:offset [start 0])
  (define-values (result _off)
    (decode-elements (wire-protocol-elements proto) data start (hasheq)))
  result)

;; Walk a list of elements, decoding each, threading offset and result.
(define (decode-elements elements data offset result)
  (if (null? elements)
      (values result offset)
      (let-values ([(new-result new-off) (decode-element (car elements) data offset result)])
        (decode-elements (cdr elements) data new-off new-result))))

;; Decode a single element.
(define (decode-element elem data offset result)
  (cond
    [(wire-field? elem)
     (decode-wire-field elem data offset result)]
    [(wire-bitfield-group? elem)
     (decode-bitfield-group elem data offset result)]
    [(wire-case? elem)
     (decode-case elem data offset result)]
    [(wire-padding? elem)
     (define w (resolve-width (wire-padding-width elem) result))
     (values result (+ offset w))]))

;; --- Field decode ---

(define (decode-wire-field elem data offset result)
  (define name (wire-field-name elem))
  (define type (wire-field-type elem))
  (define order (wire-field-byte-order elem))
  (define opts (wire-field-options elem))
  (define present-when (wire-option opts 'present-when))

  (if (and present-when
           (not (present-when (λ (n) (hash-ref result n #f)))))
      ;; Absent: store #f, don't advance
      (values (hash-set result name #f) offset)
      ;; Present: decode
      (let ()
        (define w (resolve-width (wire-field-width elem)
                    (λ (n)
                      (case n
                        [(#:remaining) (- (bytes-length data) offset)]
                        [(#:data) data]
                        [(#:offset) offset]
                        [else (hash-ref result n #f)]))))
        (define raw-val (decode-value type data offset w order))
        (define val (apply-decode-transforms raw-val opts))
        (values (hash-set result name val) (+ offset w)))))


;; --- Bitfield group decode ---

(define (decode-bitfield-group group data offset result)
  (define fields (wire-bitfield-group-fields group))
  (define bit-order (wire-bitfield-group-bit-order group))
  (define total-bits (wire-bitfield-group-total-bits group))
  (define byte-count (quotient total-bits 8))

  ;; Read the byte span as a big-endian integer
  (define raw
    (for/fold ([acc 0]) ([i (in-range byte-count)])
      (bitwise-ior (arithmetic-shift acc 8)
                   (bytes-ref data (+ offset i)))))

  ;; Extract each field's bits
  (define new-result
    (case bit-order
      [(msb)
       (let loop ([fs fields] [bits-remaining total-bits] [res result])
         (if (null? fs) res
             (let* ([f (car fs)]
                    [w (wire-bit-field-width f)]
                    [shift (- bits-remaining w)]
                    [val (bitwise-and (arithmetic-shift raw (- shift))
                                     (sub1 (arithmetic-shift 1 w)))])
               (loop (cdr fs) shift (hash-set res (wire-bit-field-name f) val)))))]
      [(lsb)
       (let loop ([fs fields] [bit-pos 0] [res result])
         (if (null? fs) res
             (let* ([f (car fs)]
                    [w (wire-bit-field-width f)]
                    [val (bitwise-and (arithmetic-shift raw (- bit-pos))
                                     (sub1 (arithmetic-shift 1 w)))])
               (loop (cdr fs) (+ bit-pos w) (hash-set res (wire-bit-field-name f) val)))))]))

  (values new-result (+ offset byte-count)))

;; --- Case decode ---

(define (decode-case elem data offset result)
  (define disc-name (wire-case-discriminator elem))
  (define disc-val (hash-ref result disc-name))
  (define branches (wire-case-branches elem))

  ;; Find matching branch
  (define branch
    (for/first ([br branches]
                #:when (let ([pred (wire-case-branch-predicate br)])
                         (if (procedure? pred)
                             (pred disc-val)
                             (equal? pred disc-val))))
      br))

  (if branch
      (decode-elements (wire-case-branch-elements branch) data offset result)
      (values result offset)))

;; ============================================================
;; Encode: field-value hash → bytes
;; ============================================================

(define (ir-encode proto values)
  ;; First pass: compute total size
  (define size (compute-size (wire-protocol-elements proto) values))
  (define buf (make-bytes size 0))
  ;; Second pass: write fields
  (encode-elements (wire-protocol-elements proto) values buf 0)
  buf)

;; Walk elements, encoding each into the buffer.
(define (encode-elements elements values buf offset)
  (if (null? elements)
      offset
      (let ([new-off (encode-element (car elements) values buf offset)])
        (encode-elements (cdr elements) values buf new-off))))

;; Encode a single element.
(define (encode-element elem values buf offset)
  (cond
    [(wire-field? elem)
     (encode-wire-field elem values buf offset)]
    [(wire-bitfield-group? elem)
     (encode-bitfield-group elem values buf offset)]
    [(wire-case? elem)
     (encode-case elem values buf offset)]
    [(wire-padding? elem)
     (define w (resolve-width (wire-padding-width elem) values))
     (+ offset w)]))

;; --- Field encode ---

(define (encode-wire-field elem values buf offset)
  (define name (wire-field-name elem))
  (define type (wire-field-type elem))
  (define order (wire-field-byte-order elem))
  (define opts (wire-field-options elem))
  (define present-when (wire-option opts 'present-when))

  (if (and present-when
           (not (present-when (λ (n) (hash-ref values n #f)))))
      offset ;; absent: don't encode, don't advance
      (let ()
        (define w (resolve-width (wire-field-width elem) values))
        (define raw-val (hash-ref values name))
        (define val (apply-encode-transforms raw-val opts))
        (encode-value type buf offset w order val)
        (+ offset w))))

;; --- Bitfield group encode ---

(define (encode-bitfield-group group values buf offset)
  (define fields (wire-bitfield-group-fields group))
  (define bit-order (wire-bitfield-group-bit-order group))
  (define total-bits (wire-bitfield-group-total-bits group))
  (define byte-count (quotient total-bits 8))

  (define acc
    (case bit-order
      [(msb)
       (for/fold ([a 0]) ([f fields])
         (define w (wire-bit-field-width f))
         (define val (hash-ref values (wire-bit-field-name f)))
         (bitwise-ior (arithmetic-shift a w)
                      (bitwise-and val (sub1 (arithmetic-shift 1 w)))))]
      [(lsb)
       (let loop ([fs fields] [a 0] [pos 0])
         (if (null? fs) a
             (let* ([f (car fs)]
                    [w (wire-bit-field-width f)]
                    [val (hash-ref values (wire-bit-field-name f))]
                    [masked (bitwise-and val (sub1 (arithmetic-shift 1 w)))])
               (loop (cdr fs) (bitwise-ior a (arithmetic-shift masked pos)) (+ pos w)))))]))

  ;; Write as big-endian bytes
  (for ([i (in-range byte-count)])
    (bytes-set! buf (+ offset i)
                (bitwise-and (arithmetic-shift acc (* -8 (- byte-count 1 i))) #xFF)))
  (+ offset byte-count))

;; --- Case encode ---

(define (encode-case elem values buf offset)
  (define disc-name (wire-case-discriminator elem))
  (define disc-val (hash-ref values disc-name))
  (define branches (wire-case-branches elem))

  (define branch
    (for/first ([br branches]
                #:when (let ([pred (wire-case-branch-predicate br)])
                         (if (procedure? pred)
                             (pred disc-val)
                             (equal? pred disc-val))))
      br))

  (if branch
      (encode-elements (wire-case-branch-elements branch) values buf offset)
      offset))

;; ============================================================
;; Size computation
;; ============================================================

(define (compute-size elements values)
  (for/fold ([total 0]) ([elem elements])
    (+ total (element-size elem values))))

(define (element-size elem values)
  (cond
    [(wire-field? elem)
     (define opts (wire-field-options elem))
     (define present-when (wire-option opts 'present-when))
     (if (and present-when
              (not (present-when (λ (n) (hash-ref values n #f)))))
         0
         (resolve-width (wire-field-width elem) values))]
    [(wire-bitfield-group? elem)
     (quotient (wire-bitfield-group-total-bits elem) 8)]
    [(wire-case? elem)
     (define disc-val (hash-ref values (wire-case-discriminator elem)))
     (define branch
       (for/first ([br (wire-case-branches elem)]
                   #:when (let ([pred (wire-case-branch-predicate br)])
                            (if (procedure? pred)
                                (pred disc-val)
                                (equal? pred disc-val))))
         br))
     (if branch
         (compute-size (wire-case-branch-elements branch) values)
         0)]
    [(wire-padding? elem)
     (resolve-width (wire-padding-width elem) values)]))

;; ============================================================
;; Helpers
;; ============================================================

;; Resolve a width to an integer.
(define (resolve-width w values-or-lookup)
  (define lk (if (procedure? values-or-lookup)
                 values-or-lookup
                 (λ (name) (hash-ref values-or-lookup name #f))))
  (cond
    [(width-fixed? w) (width-fixed-value w)]
    [(width-field-ref? w) (lk (width-field-ref-name w))]
    [(width-compute? w) ((width-compute-fn w) lk)]
    [(exact-positive-integer? w) w]
    [else (error 'resolve-width "invalid width: ~e" w)]))

;; Decode a single value from bytes.
(define (decode-value type data offset width order)
  (case type
    [(uint)    (decode-uint data offset width order)]
    [(sint)    (decode-sint data offset width order)]
    [(alpha)   (decode-alpha data offset width)]
    [(octets)  (if (zero? width) (bytes) (subbytes data offset (+ offset width)))]
    [(bool)    (not (zero? (bytes-ref data offset)))]
    [(float32) (floating-point-bytes->real (subbytes data offset (+ offset 4)) (eq? order 'big))]
    [(float64) (floating-point-bytes->real (subbytes data offset (+ offset 8)) (eq? order 'big))]
    [(utf8)    (bytes->string/utf-8
                (let ([raw (subbytes data offset (+ offset width))])
                  (let loop ([end (bytes-length raw)])
                    (if (and (> end 0) (zero? (bytes-ref raw (sub1 end))))
                        (loop (sub1 end))
                        (subbytes raw 0 end)))))]
    [else (error 'decode-value "unknown type: ~e" type)]))

;; Encode a single value into buffer.
(define (encode-value type buf offset width order val)
  (case type
    [(uint)    (encode-uint buf offset width order val)]
    [(sint)    (encode-sint buf offset width order val)]
    [(alpha)   (encode-alpha buf offset width val)]
    [(octets)  (when (and (bytes? val) (> (bytes-length val) 0))
                 (bytes-copy! buf offset val 0 (min (bytes-length val) width)))]
    [(bool)    (bytes-set! buf offset (if val 1 0))]
    [(float32) (bytes-copy! buf offset (real->floating-point-bytes val 4 (eq? order 'big)))]
    [(float64) (bytes-copy! buf offset (real->floating-point-bytes val 8 (eq? order 'big)))]
    [(utf8)    (let ([src (string->bytes/utf-8 val)])
                 (bytes-copy! buf offset src 0 (min (bytes-length src) width)))]
    [else (error 'encode-value "unknown type: ~e" type)]))

;; --- Uint encode/decode ---

(define (decode-uint data offset width order)
  (case order
    [(big)
     (for/fold ([acc 0]) ([i (in-range width)])
       (bitwise-ior (arithmetic-shift acc 8) (bytes-ref data (+ offset i))))]
    [(little)
     (for/fold ([acc 0]) ([i (in-range (sub1 width) -1 -1)])
       (bitwise-ior (arithmetic-shift acc 8) (bytes-ref data (+ offset i))))]))

(define (encode-uint buf offset width order val)
  (case order
    [(big)
     (for ([i (in-range (sub1 width) -1 -1)])
       (bytes-set! buf (+ offset (- (sub1 width) i))
                   (bitwise-and (arithmetic-shift val (* -8 i)) #xFF)))]
    [(little)
     (for ([i (in-range width)])
       (bytes-set! buf (+ offset i)
                   (bitwise-and (arithmetic-shift val (* -8 i)) #xFF)))]))

(define (decode-sint data offset width order)
  (define unsigned (decode-uint data offset width order))
  (define sign-bit (expt 2 (sub1 (* 8 width))))
  (if (>= unsigned sign-bit) (- unsigned (expt 256 width)) unsigned))

(define (encode-sint buf offset width order val)
  (encode-uint buf offset width order
               (if (negative? val) (+ val (expt 256 width)) val)))

(define (decode-alpha data offset width)
  (define raw (subbytes data offset (+ offset width)))
  (regexp-replace #rx" +$" (bytes->string/latin-1 raw) ""))

(define (encode-alpha buf offset width val)
  (define src (string->bytes/latin-1 val))
  (define len (min (bytes-length src) width))
  (bytes-copy! buf offset src 0 len)
  (for ([i (in-range len width)])
    (bytes-set! buf (+ offset i) (char->integer #\space))))

;; --- Transforms ---

(define (apply-decode-transforms val opts)
  (define dt (wire-option opts 'decode-transform))
  (define enum (wire-option opts 'enum))
  (cond
    [dt (dt val)]
    [enum (enum val)]  ;; wire-enum-lookup
    [else val]))

(define (apply-encode-transforms val opts)
  (define et (wire-option opts 'encode-transform))
  (define enum (wire-option opts 'enum))
  (cond
    [et (et val)]
    [enum (enum val)]  ;; wire-enum-ref
    [else val]))

