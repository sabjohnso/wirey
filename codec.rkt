#lang racket/base

(require wirey/field
         wirey/protocol
         wirey/length-expr
         wirey/case-block)

(provide encode
         decode
         decode-field
         decode-bitfield
         decode-repeated-struct
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
    (for/fold ([v values]) ([f (in-list fields)]
                            #:when (field-desc? f))
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
  (for ([f (in-list fields)]
        #:when (field-desc? f))
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
        ;; Case block
        [(case-block? (car fields))
         (define flush (if (zero? bit-acc) 0 (quotient bit-acc 8)))
         (define cb (car fields))
         (define disc-val (hash-ref effective-values (case-block-discriminator cb)))
         (define br (case-block-select-branch cb disc-val))
         (define branch-size
           (if br
               (for/sum ([bf (in-list (case-branch-fields br))])
                 (define raw-w (field-desc-width bf))
                 (cond
                   [(exact-positive-integer? raw-w) raw-w]
                   [(or (compute? raw-w) (field-ref? raw-w))
                    (eval-length-expr raw-w
                      (λ (name)
                        (case name
                          [(#:data) #f]   ;; no data buffer during size computation
                          [(#:offset) #f]
                          [else (hash-ref effective-values name #f)])))]
                   [else (resolve-width bf effective-values)]))
               0))
         (loop (cdr fields) 0 (+ total flush branch-size))]
        [(and (field-desc-conditional? (car fields))
              (not (field-present? (car fields))))
         (loop (cdr fields) bit-acc total)]
        [(eq? (field-desc-unit (car fields)) 'bits)
         (loop (cdr fields) (+ bit-acc (field-desc-width (car fields))) total)]
        [else
         (define flush (if (zero? bit-acc) 0 (quotient bit-acc 8)))
         (define f (car fields))
         (define w (resolve-width f effective-values))
         (define rep (field-desc-repeat f))
         (define rep-until (field-desc-repeat-until f))
         (define count (cond
                         [rep-until
                          (+ 1 (length (hash-ref effective-values (field-desc-name f))))]
                         [(not rep) 1]
                         [(exact-positive-integer? rep) rep]
                         [else (eval-length-expr rep (λ (name) (hash-ref effective-values name)))]))
         (loop (cdr fields) 0 (+ total flush (* w count)))])))
  (define buf (make-bytes total 0))
  ;; First pass: encode all fields (computed fields get 0)
  (define computed-fields '()) ;; list of (field-desc . byte-offset)
  (let loop ([fields fields] [byte-off 0])
    (cond
      [(null? fields) (void)]
      ;; Case block: encode the matching branch
      [(case-block? (car fields))
       (define cb (car fields))
       (define disc-val (hash-ref effective-values (case-block-discriminator cb)))
       (define br (case-block-select-branch cb disc-val))
       (define new-off
         (if br
             (let inner-loop ([bfs (case-branch-fields br)] [off byte-off])
               (if (null? bfs)
                   off
                   (let ([bf (car bfs)])
                     (define raw-w (field-desc-width bf))
                     (define w
                       (cond
                         [(exact-positive-integer? raw-w) raw-w]
                         [(or (compute? raw-w) (field-ref? raw-w))
                          (eval-length-expr raw-w
                            (λ (name)
                              (case name
                                [(#:data) #f]
                                [(#:offset) #f]
                                [else (hash-ref effective-values name #f)])))]
                         [else (resolve-width bf effective-values)]))
                     (encode-field! buf off bf w (hash-ref effective-values (field-desc-name bf)))
                     (inner-loop (cdr bfs) (+ off w)))))
             byte-off))
       (loop (cdr fields) new-off)]
      ;; Skip absent conditional fields
      [(and (field-desc? (car fields))
            (field-desc-conditional? (car fields))
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
       (cond
         ;; Repeated field: encode each element
         [(field-desc-repeat-until f)
          ;; Encode all elements + sentinel (zero value of the field width)
          (define vals (hash-ref effective-values (field-desc-name f)))
          (let rep-loop ([items vals] [off byte-off])
            (if (null? items)
                ;; Write sentinel (buffer is pre-zeroed, just advance)
                (loop (cdr fields) (+ off w))
                (begin
                  (encode-field! buf off f w (car items))
                  (rep-loop (cdr items) (+ off w)))))]
         [(field-desc-repeat f)
          (define rep (field-desc-repeat f))
          (define count (if (exact-positive-integer? rep)
                            rep
                            (eval-length-expr rep (λ (name) (hash-ref effective-values name)))))
          (define vals (hash-ref effective-values (field-desc-name f)))
          (let rep-loop ([items vals] [off byte-off])
            (unless (null? items)
              (encode-field! buf off f w (car items))
              (rep-loop (cdr items) (+ off w))))
          (loop (cdr fields) (+ byte-off (* w count)))]
         [else
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
          (loop (cdr fields) (+ byte-off w))])]))
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
  (define term (field-desc-terminator fd))
  (case type
    [(uint)    (encode-uint! buf offset width order val)]
    [(sint)    (encode-sint! buf offset width order val)]
    [(alpha)   (encode-alpha! buf offset width val term)]
    [(octets)  (encode-octets! buf offset width val)]
    [(padding) (void)]
    [(float32) (encode-float! buf offset 4 order val)]
    [(float64) (encode-float! buf offset 8 order val)]
    [(bool)    (bytes-set! buf offset (if val 1 0))]
    [(bcd)     (encode-bcd! buf offset width val)]
    [(utf8)    (encode-utf8! buf offset width val)]
    [(utf16)   (encode-utf16! buf offset width order val)]
    [(utf32)   (encode-utf32! buf offset width order val)]))

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

(define (encode-alpha! buf offset width val [terminator #f])
  (define src (string->bytes/latin-1 val))
  (define len (min (bytes-length src) width))
  (bytes-copy! buf offset src 0 len)
  (cond
    [terminator
     ;; Write terminator after string, pad rest with zeros
     (when (< len width)
       (bytes-set! buf (+ offset len) terminator))
     ;; Remaining bytes are already 0 from make-bytes
     ]
    [else
     ;; Space-pad
     (for ([i (in-range len width)])
       (bytes-set! buf (+ offset i) (char->integer #\space)))]))

(define (encode-octets! buf offset width val)
  (bytes-copy! buf offset val 0 (min (bytes-length val) width)))

(define (encode-float! buf offset size order val)
  (define big? (eq? order 'big))
  (define fbs (real->floating-point-bytes val size big?))
  (bytes-copy! buf offset fbs))

(define (encode-bcd! buf offset width val)
  ;; Packed BCD: two digits per byte, right-aligned, zero-padded
  (define digits (* width 2))
  (define s (number->string val))
  (define padded (string-append (make-string (max 0 (- digits (string-length s))) #\0) s))
  (for ([i (in-range width)])
    (define hi (- (char->integer (string-ref padded (* i 2))) (char->integer #\0)))
    (define lo (- (char->integer (string-ref padded (+ (* i 2) 1))) (char->integer #\0)))
    (bytes-set! buf (+ offset i) (bitwise-ior (arithmetic-shift hi 4) lo))))

;; ============================================================
;; Decoding: protocol-desc + bytes + offset → hash
;; ============================================================

(define (decode pd data #:offset [start 0])
  (define fields (protocol-desc-fields pd))
  (let loop ([fields fields] [byte-off start] [bit-off 0] [result (hasheq)])
    (cond
      [(null? fields)
       result]
      ;; Case block: dispatch on discriminator, decode matching branch
      [(case-block? (car fields))
       (define cb (car fields))
       (define disc-val (hash-ref result (case-block-discriminator cb)))
       (define br (case-block-select-branch cb disc-val))
       (define-values (new-result new-off)
         (if br
             (let inner ([bfs (case-branch-fields br)] [off byte-off] [res result])
               (if (null? bfs)
                   (values res off)
                   (let* ([bf (car bfs)]
                          [raw-w (field-desc-width bf)]
                          ;; Resolve variable-length widths (forgiving lookup for cross-case refs)
                          ;; Pass #:data and #:offset for struct-size-at computes
                          [w (cond
                               [(exact-positive-integer? raw-w) raw-w]
                               [(field-ref? raw-w)
                                (eval-length-expr raw-w (λ (name) (hash-ref res name #f)))]
                               [(compute? raw-w)
                                (eval-length-expr raw-w
                                  (λ (name)
                                    (case name
                                      [(#:data) data]
                                      [(#:offset) off]
                                      [else (hash-ref res name #f)])))]
                               [else raw-w])]
                          [val (if (eq? (field-desc-type bf) 'padding)
                                   (void)
                                   (decode-field-with-width data off bf w))])
                     (inner (cdr bfs)
                            (+ off (if (and (integer? w) (>= w 0)) w 0))
                            (if (eq? (field-desc-type bf) 'padding)
                                res
                                (hash-set res (field-desc-name bf) val))))))
             (values result byte-off)))
       (loop (cdr fields) new-off 0 new-result)]
      ;; Conditional field: check presence predicate
      [(and (field-desc? (car fields)) (field-desc-conditional? (car fields)))
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
                                       (λ (name)
                                         (case name
                                           [(#:data) data]
                                           [(#:offset) byte-off]
                                           [else (hash-ref result name #f)])))
                     (field-desc-width f)))
       (cond
         [(eq? (field-desc-type f) 'padding)
          ;; Skip padding
          (loop (cdr fields) (+ byte-off w) 0 result)]
         [(field-desc-repeat-until f)
          ;; Decode elements until predicate returns true
          (define pred (field-desc-repeat-until f))
          (define-values (items end-off)
            (let rep-loop ([off byte-off] [acc '()])
              (define val (decode-field-with-width data off f w))
              (if (pred val)
                  (values (reverse acc) (+ off w))  ;; consume sentinel
                  (rep-loop (+ off w) (cons val acc)))))
          (loop (cdr fields) end-off 0
                (hash-set result (field-desc-name f) items))]
         [(field-desc-repeat f)
          ;; Decode N elements into a list
          (define rep (field-desc-repeat f))
          (define count (if (exact-positive-integer? rep)
                            rep
                            (eval-length-expr rep (λ (name) (hash-ref result name)))))
          (define-values (items end-off)
            (let rep-loop ([n count] [off byte-off] [acc '()])
              (if (zero? n)
                  (values (reverse acc) off)
                  (let ([val (decode-field-with-width data off f w)])
                    (rep-loop (sub1 n) (+ off w) (cons val acc))))))
          (loop (cdr fields) end-off 0
                (hash-set result (field-desc-name f) items))]
         [else
          (let ([val (decode-field-with-width data byte-off f w)])
            (loop (cdr fields) (+ byte-off w) 0
                  (hash-set result (field-desc-name f) val)))])])))

;; Collect contiguous bit-unit fields that share the same effective bit order.
;; Splits when bit order changes between fields.
(define (collect-bitfield-group fields)
  (define (effective-order f)
    (or (field-desc-bit-order f) 'msb))
  (let loop ([fs fields] [group '()] [bits 0] [group-order #f])
    (cond
      [(and (pair? fs)
            (field-desc? (car fs))
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
  (define term (field-desc-terminator fd))
  (case type
    [(uint)    (decode-uint data offset width order)]
    [(sint)    (decode-sint data offset width order)]
    [(alpha)   (decode-alpha data offset width term)]
    [(octets)  (if (zero? width) (bytes) (decode-octets data offset width))]
    [(padding) (void)]
    [(float32) (decode-float data offset 4 order)]
    [(float64) (decode-float data offset 8 order)]
    [(bool)    (not (zero? (bytes-ref data offset)))]
    [(bcd)     (decode-bcd data offset width)]
    [(utf8)    (decode-utf8 data offset width term)]
    [(utf16)   (decode-utf16 data offset width order term)]
    [(utf32)   (decode-utf32 data offset width order term)]))

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

(define (decode-alpha data offset width [terminator #f])
  (define raw (subbytes data offset (+ offset width)))
  (if terminator
      ;; Scan for terminator byte, return string up to it
      (let loop ([i 0])
        (cond
          [(>= i (bytes-length raw))
           (bytes->string/latin-1 raw)]
          [(= (bytes-ref raw i) terminator)
           (bytes->string/latin-1 (subbytes raw 0 i))]
          [else (loop (add1 i))]))
      ;; Space-pad trim
      (string-trim-right (bytes->string/latin-1 raw))))

(define (decode-octets data offset width)
  (subbytes data offset (+ offset width)))

(define (string-trim-right s)
  (regexp-replace #rx" +$" s ""))

(define (decode-float data offset size order)
  (define big? (eq? order 'big))
  (floating-point-bytes->real (subbytes data offset (+ offset size)) big?))

(define (encode-utf8! buf offset width val)
  (define src (string->bytes/utf-8 val))
  (define len (min (bytes-length src) width))
  (bytes-copy! buf offset src 0 len))
  ;; remainder is already 0 (null-padded by make-bytes)

(define (decode-utf8 data offset width [terminator #f])
  (define raw (subbytes data offset (+ offset width)))
  (define term-byte (or terminator 0))
  ;; Trim trailing terminator/null bytes
  (define trimmed
    (let loop ([end (bytes-length raw)])
      (if (and (> end 0) (= (bytes-ref raw (sub1 end)) term-byte))
          (loop (sub1 end))
          (subbytes raw 0 end))))
  (bytes->string/utf-8 trimmed))

(define (encode-utf16! buf offset width order val)
  (define big? (eq? order 'big))
  (define chars (string->list val))
  (let loop ([cs chars] [off offset])
    (when (and (pair? cs) (< (+ off 1) (+ offset width)))
      (define cp (char->integer (car cs)))
      (if big?
          (begin (bytes-set! buf off (arithmetic-shift cp -8))
                 (bytes-set! buf (+ off 1) (bitwise-and cp #xFF)))
          (begin (bytes-set! buf off (bitwise-and cp #xFF))
                 (bytes-set! buf (+ off 1) (arithmetic-shift cp -8))))
      (loop (cdr cs) (+ off 2)))))

(define (decode-utf16 data offset width order [terminator #f])
  (define big? (eq? order 'big))
  (define term-cp (or terminator 0))
  (define chars
    (let loop ([off offset] [acc '()])
      (if (>= (+ off 1) (+ offset width))
          (reverse acc)
          (let ([hi (bytes-ref data off)]
                [lo (bytes-ref data (+ off 1))])
            (define cp (if big?
                           (bitwise-ior (arithmetic-shift hi 8) lo)
                           (bitwise-ior (arithmetic-shift lo 8) hi)))
            (if (= cp term-cp)
                (reverse acc)
                (loop (+ off 2) (cons (integer->char cp) acc)))))))
  (apply string chars))

(define (encode-utf32! buf offset width order val)
  (define big? (eq? order 'big))
  (define chars (string->list val))
  (let loop ([cs chars] [off offset])
    (when (and (pair? cs) (<= (+ off 3) (+ offset width -1)))
      (define cp (char->integer (car cs)))
      (if big?
          (begin (bytes-set! buf off (arithmetic-shift cp -24))
                 (bytes-set! buf (+ off 1) (bitwise-and (arithmetic-shift cp -16) #xFF))
                 (bytes-set! buf (+ off 2) (bitwise-and (arithmetic-shift cp -8) #xFF))
                 (bytes-set! buf (+ off 3) (bitwise-and cp #xFF)))
          (begin (bytes-set! buf off (bitwise-and cp #xFF))
                 (bytes-set! buf (+ off 1) (bitwise-and (arithmetic-shift cp -8) #xFF))
                 (bytes-set! buf (+ off 2) (bitwise-and (arithmetic-shift cp -16) #xFF))
                 (bytes-set! buf (+ off 3) (arithmetic-shift cp -24))))
      (loop (cdr cs) (+ off 4)))))

(define (decode-utf32 data offset width order [terminator #f])
  (define big? (eq? order 'big))
  (define term-cp (or terminator 0))
  (define chars
    (let loop ([off offset] [acc '()])
      (if (> (+ off 3) (+ offset width -1))
          (reverse acc)
          (let ([cp (if big?
                        (bitwise-ior (arithmetic-shift (bytes-ref data off) 24)
                                     (arithmetic-shift (bytes-ref data (+ off 1)) 16)
                                     (arithmetic-shift (bytes-ref data (+ off 2)) 8)
                                     (bytes-ref data (+ off 3)))
                        (bitwise-ior (bytes-ref data off)
                                     (arithmetic-shift (bytes-ref data (+ off 1)) 8)
                                     (arithmetic-shift (bytes-ref data (+ off 2)) 16)
                                     (arithmetic-shift (bytes-ref data (+ off 3)) 24)))])
            (if (= cp term-cp)
                (reverse acc)
                (loop (+ off 4) (cons (integer->char cp) acc)))))))
  (apply string chars))

(define (decode-bcd data offset width)
  (for/fold ([acc 0]) ([i (in-range width)])
    (define b (bytes-ref data (+ offset i)))
    (define hi (arithmetic-shift b -4))
    (define lo (bitwise-and b #x0F))
    (+ (* acc 100) (* hi 10) lo)))

;; Decode N instances of a struct, advancing through the buffer.
;; decode-fn: (bytes #:offset n) → struct-instance
;; size-fn: (bytes offset) → bytes-consumed
;; Returns: (values (listof instance) end-offset)
(define (decode-repeated-struct data offset count decode-fn size-fn)
  (let loop ([n count] [off offset] [acc '()])
    (if (zero? n)
        (values (reverse acc) off)
        (let ([instance (decode-fn data #:offset off)]
              [consumed (size-fn data off)])
          (loop (sub1 n) (+ off consumed) (cons instance acc))))))
