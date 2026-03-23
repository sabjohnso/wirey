#lang racket/base

(require wirey/field
         wirey/protocol
         wirey/length-expr)

(provide encode
         decode
         decode-field
         decode-bitfield
         resolve-group-bit-order
         collect-bitfield-group)

;; ============================================================
;; Resolve a field's width to an integer, given values hash
;; ============================================================

(define (resolve-width fd values)
  (define w (field-desc-width fd))
  (if (exact-positive-integer? w)
      w
      (eval-length-expr w (λ (name) (hash-ref values name)))))

;; ============================================================
;; Encoding: protocol-desc + hash → bytes
;; ============================================================

(define (encode pd values)
  (define fields (protocol-desc-fields pd))
  ;; For computed and padding fields, use 0 as placeholder in values
  (define effective-values
    (for/fold ([v values]) ([f (in-list fields)])
      (if (or (field-desc-computed? f)
              (eq? (field-desc-type f) 'padding))
          (hash-set v (field-desc-name f) 0)
          v)))
  ;; Helper: check if a conditional field is present
  (define (field-present? f)
    (define pw (field-desc-present-when f))
    (or (not pw)
        (pw (λ (name) (hash-ref effective-values name)))))
  ;; Validate contracts on non-computed, non-padding, present fields
  (for ([f (in-list fields)])
    (when (and (field-desc-has-contract? f)
               (not (field-desc-computed? f))
               (not (eq? (field-desc-type f) 'padding))
               (field-present? f))
      (define name (field-desc-name f))
      (define val (hash-ref effective-values name))
      (define contract-fn (field-desc-contract f))
      (unless (contract-fn val)
        (error 'encode
               "field '~a': contract violation, value ~e rejected"
               name val))))
  ;; Compute total size by resolving all widths (skip absent conditional fields)
  (define total
    (let loop ([fields fields] [bit-acc 0] [total 0])
      (cond
        [(null? fields)
         (+ total (quotient bit-acc 8))]
        [(and (field-desc-conditional? (car fields))
              (not (field-present? (car fields))))
         (loop (cdr fields) bit-acc total)]
        [(eq? (field-desc-unit (car fields)) 'bits)
         (loop (cdr fields) (+ bit-acc (field-desc-width (car fields))) total)]
        [else
         (define flush (if (zero? bit-acc) 0 (quotient bit-acc 8)))
         (define w (resolve-width (car fields) effective-values))
         (loop (cdr fields) 0 (+ total flush w))])))
  (define buf (make-bytes total 0))
  ;; First pass: encode all fields (computed fields get 0)
  (define computed-fields '()) ;; list of (field-desc . byte-offset)
  (let loop ([fields fields] [byte-off 0])
    (cond
      [(null? fields) (void)]
      ;; Skip absent conditional fields
      [(and (field-desc-conditional? (car fields))
            (not (field-present? (car fields))))
       (loop (cdr fields) byte-off)]
      [(eq? (field-desc-unit (car fields)) 'bits)
       ;; Collect entire bitfield group and encode as a unit
       (define-values (group group-bits remaining)
         (collect-bitfield-group fields))
       (define group-bytes (quotient group-bits 8))
       (define bit-ord (resolve-group-bit-order group))
       (encode-bitfield-group! buf byte-off group group-bits bit-ord effective-values)
       (loop remaining (+ byte-off group-bytes))]
      [else
       (define f (car fields))
       (define w (resolve-width f effective-values))
       ;; Validate variable-length data consistency
       (when (field-desc-variable-length? f)
         (define val (hash-ref effective-values (field-desc-name f)))
         (when (bytes? val)
           (unless (= (bytes-length val) w)
             (error 'encode
                    "field '~a': length expression evaluates to ~a but data is ~a bytes"
                    (field-desc-name f) w (bytes-length val)))))
       ;; Track computed fields for second pass
       (when (field-desc-computed? f)
         (set! computed-fields (cons (cons f byte-off) computed-fields)))
       (encode-field! buf byte-off f w (hash-ref effective-values (field-desc-name f)))
       (loop (cdr fields) (+ byte-off w))]))
  ;; Second pass: compute and write computed field values
  (for ([entry (in-list computed-fields)])
    (define f (car entry))
    (define off (cdr entry))
    (define compute-fn (field-desc-compute f))
    (define computed-val (compute-fn buf))
    (define w (field-desc-width f))
    (encode-field! buf off f w computed-val))
  buf)

;; Resolve the effective bit order for a bitfield group.
;; Default is MSB. Any field with explicit #:bit-order overrides.
(define (resolve-group-bit-order group)
  (define explicit
    (for/first ([f (in-list group)]
                #:when (field-desc-bit-order f))
      (field-desc-bit-order f)))
  (or explicit 'msb))

;; Encode a bitfield group into the buffer.
(define (encode-bitfield-group! buf byte-off group group-bits bit-ord vals)
  (define group-bytes (quotient group-bits 8))
  (define acc
    (case bit-ord
      [(msb)
       ;; MSB-first: shift left and OR new value
       (for/fold ([a 0]) ([f (in-list group)])
         (define w (field-desc-width f))
         (define val (hash-ref vals (field-desc-name f)))
         (bitwise-ior (arithmetic-shift a w)
                      (bitwise-and val (sub1 (arithmetic-shift 1 w)))))]
      [(lsb)
       ;; LSB-first: OR new value shifted left by accumulated bit position
       (let lsb-loop ([fs group] [a 0] [pos 0])
         (if (null? fs)
             a
             (let* ([f (car fs)]
                    [w (field-desc-width f)]
                    [val (hash-ref vals (field-desc-name f))]
                    [masked (bitwise-and val (sub1 (arithmetic-shift 1 w)))])
               (lsb-loop (cdr fs)
                          (bitwise-ior a (arithmetic-shift masked pos))
                          (+ pos w)))))]))
  ;; Write as big-endian bytes
  (for ([i (in-range group-bytes)])
    (bytes-set! buf (+ byte-off i)
                (bitwise-and
                 (arithmetic-shift acc (* -8 (- group-bytes 1 i)))
                 #xFF))))

(define (encode-field! buf offset fd width val)
  (define type (field-desc-type fd))
  (define order (field-desc-byte-order fd))
  (case type
    [(uint)    (encode-uint! buf offset width order val)]
    [(sint)    (encode-sint! buf offset width order val)]
    [(alpha)   (encode-alpha! buf offset width val)]
    [(octets)  (encode-octets! buf offset width val)]
    [(padding) (void)]))

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
  (for ([i (in-range len width)])
    (bytes-set! buf (+ offset i) (char->integer #\space))))

(define (encode-octets! buf offset width val)
  (bytes-copy! buf offset val 0 (min (bytes-length val) width)))

;; ============================================================
;; Decoding: protocol-desc + bytes + offset → hash
;; ============================================================

(define (decode pd data #:offset [start 0])
  (define fields (protocol-desc-fields pd))
  (let loop ([fields fields] [byte-off start] [bit-off 0] [result (hasheq)])
    (cond
      [(null? fields)
       result]
      ;; Conditional field: check presence predicate
      [(field-desc-conditional? (car fields))
       (define f (car fields))
       (define pw (field-desc-present-when f))
       (if (pw (λ (name) (hash-ref result name)))
           ;; Present: decode normally (re-enter loop without the conditional flag)
           ;; We temporarily wrap in a non-conditional desc for re-entry
           (let* ([w (if (field-desc-variable-length? f)
                         (eval-length-expr (field-desc-width f)
                                           (λ (name) (hash-ref result name)))
                         (field-desc-width f))]
                  [val (decode-field-with-width data byte-off f w)])
             (loop (cdr fields) (+ byte-off w) 0
                   (hash-set result (field-desc-name f) val)))
           ;; Absent: store #f and don't advance offset
           (loop (cdr fields) byte-off bit-off
                 (hash-set result (field-desc-name f) #f)))]
      [(eq? (field-desc-unit (car fields)) 'bits)
       (define-values (group-fields group-bits remaining)
         (collect-bitfield-group fields))
       (define group-bytes (quotient group-bits 8))
       (define bit-ord (resolve-group-bit-order group-fields))
       (define raw
         (for/fold ([acc 0]) ([i (in-range group-bytes)])
           (bitwise-ior (arithmetic-shift acc 8)
                        (bytes-ref data (+ byte-off i)))))
       (define new-result
         (case bit-ord
           [(msb)
            (let extract ([fs group-fields] [bits-remaining group-bits] [res result])
              (if (null? fs)
                  res
                  (let* ([gf (car fs)]
                         [gw (field-desc-width gf)]
                         [shift (- bits-remaining gw)]
                         [val (bitwise-and (arithmetic-shift raw (- shift))
                                           (sub1 (arithmetic-shift 1 gw)))]
                         [final-val (if (eq? (field-desc-type gf) 'sint)
                                        (sint-from-bits val gw)
                                        val)])
                    (extract (cdr fs) shift
                             (hash-set res (field-desc-name gf) final-val)))))]
           [(lsb)
            (let extract ([fs group-fields] [bit-pos 0] [res result])
              (if (null? fs)
                  res
                  (let* ([gf (car fs)]
                         [gw (field-desc-width gf)]
                         [val (bitwise-and (arithmetic-shift raw (- bit-pos))
                                           (sub1 (arithmetic-shift 1 gw)))]
                         [final-val (if (eq? (field-desc-type gf) 'sint)
                                        (sint-from-bits val gw)
                                        val)])
                    (extract (cdr fs) (+ bit-pos gw)
                             (hash-set res (field-desc-name gf) final-val)))))]))
       (loop remaining (+ byte-off group-bytes) 0 new-result)]
      [else
       (define f (car fields))
       (define w (if (field-desc-variable-length? f)
                     (eval-length-expr (field-desc-width f)
                                       (λ (name) (hash-ref result name)))
                     (field-desc-width f)))
       (if (eq? (field-desc-type f) 'padding)
           ;; Skip padding — advance offset but don't add to result
           (loop (cdr fields) (+ byte-off w) 0 result)
           (let ([val (decode-field-with-width data byte-off f w)])
             (loop (cdr fields) (+ byte-off w) 0
                   (hash-set result (field-desc-name f) val))))])))

;; Collect contiguous bit-unit fields that share the same effective bit order.
;; Splits when bit order changes between fields.
(define (collect-bitfield-group fields)
  (define (effective-order f)
    (or (field-desc-bit-order f) 'msb))
  (let loop ([fs fields] [group '()] [bits 0] [group-order #f])
    (cond
      [(and (pair? fs)
            (eq? (field-desc-unit (car fs)) 'bits)
            (or (not group-order)
                (eq? group-order (effective-order (car fs)))))
       (define f (car fs))
       (loop (cdr fs) (cons f group)
             (+ bits (field-desc-width f))
             (or group-order (effective-order f)))]
      [else
       (values (reverse group) bits fs)])))

(define (sint-from-bits val bit-width)
  (define sign-bit (arithmetic-shift 1 (sub1 bit-width)))
  (if (>= val sign-bit)
      (- val (arithmetic-shift 1 bit-width))
      val))

;; Decode a single field with an explicit width (for variable-length support)
(define (decode-field-with-width data offset fd width)
  (define type (field-desc-type fd))
  (define order (field-desc-byte-order fd))
  (case type
    [(uint)    (decode-uint data offset width order)]
    [(sint)    (decode-sint data offset width order)]
    [(alpha)   (decode-alpha data offset width)]
    [(octets)  (decode-octets data offset width)]
    [(padding) (void)]))

;; Decode a single field using its own width (byte-unit, fixed-width only)
(define (decode-field data offset fd)
  (decode-field-with-width data offset fd (field-desc-width fd)))

;; Decode a single bitfield from a byte span.
;; bit-order: 'msb or 'lsb (default 'msb for backward compatibility)
(define (decode-bitfield data group-byte-off group-bytes bit-offset bit-width type
                         #:bit-order [bit-ord 'msb])
  (define raw
    (for/fold ([acc 0]) ([i (in-range group-bytes)])
      (bitwise-ior (arithmetic-shift acc 8)
                   (bytes-ref data (+ group-byte-off i)))))
  (define val
    (case bit-ord
      [(msb)
       (define total-bits (* 8 group-bytes))
       (define shift (- total-bits bit-offset bit-width))
       (bitwise-and (arithmetic-shift raw (- shift))
                    (sub1 (arithmetic-shift 1 bit-width)))]
      [(lsb)
       (bitwise-and (arithmetic-shift raw (- bit-offset))
                    (sub1 (arithmetic-shift 1 bit-width)))]))
  (if (eq? type 'sint)
      (sint-from-bits val bit-width)
      val))

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

(define (string-trim-right s)
  (regexp-replace #rx" +$" s ""))
