#lang racket/base

;; ============================================================
;; CBOR Wire Structure (RFC 8949)
;;
;; Definite-length CBOR items expressed via struct/wire.
;; This proves wirey's DSL can describe self-describing recursive
;; formats. Indefinite-length encoding is handled by a thin
;; wrapper that reuses this definition.
;; ============================================================

(require racket/list
         wirey/syntax
         wirey/protocol
         wirey/codec)

(provide (all-defined-out)
         cbor-wire-item-encode-value
         cbor-wire-item-decode-value
         cbor-wire-item->racket
         cbor-wire-encode-unsigned
         cbor-wire-encode-negative
         cbor-wire-encode-bytes
         cbor-wire-encode-text
         cbor-wire-encode-array
         cbor-wire-encode-map
         cbor-wire-encode-tag
         cbor-wire-encode-simple
         cbor-wire-encode-float)

;; The core CBOR wire structure.
;; Each item has an initial byte (major-type + additional-info),
;; an optional extended argument, and a type-dependent payload.
;; Forward declarations for recursive encode/decode
(define (cbor-racket->fields v)
  (cond
    ;; Boolean
    [(eq? v #t) (hasheq 'major-type 7 'additional-info 21)]
    [(eq? v #f) (hasheq 'major-type 7 'additional-info 20)]
    ;; Null
    [(eq? v 'null) (hasheq 'major-type 7 'additional-info 22)]
    ;; Non-negative integer
    [(and (integer? v) (exact? v) (>= v 0))
     (define-values (ai ext) (argument->ai+ext v))
     (if ext
         (hasheq 'major-type 0 'additional-info ai 'ext-arg ext)
         (hasheq 'major-type 0 'additional-info ai))]
    ;; Negative integer
    [(and (integer? v) (exact? v) (< v 0))
     (define arg (- -1 v))
     (define-values (ai ext) (argument->ai+ext arg))
     (if ext
         (hasheq 'major-type 1 'additional-info ai 'ext-arg ext)
         (hasheq 'major-type 1 'additional-info ai))]
    ;; Byte string
    [(bytes? v)
     (define-values (ai ext) (argument->ai+ext (bytes-length v)))
     (if ext
         (hasheq 'major-type 2 'additional-info ai 'ext-arg ext 'payload v)
         (hasheq 'major-type 2 'additional-info ai 'payload v))]
    ;; Text string
    [(string? v)
     (define utf8 (string->bytes/utf-8 v))
     (define-values (ai ext) (argument->ai+ext (bytes-length utf8)))
     (if ext
         (hasheq 'major-type 3 'additional-info ai 'ext-arg ext 'payload utf8)
         (hasheq 'major-type 3 'additional-info ai 'payload utf8))]
    ;; List → array
    [(list? v)
     (define item-bytes (map (λ (item) (cbor-wire-item-encode-value item)) v))
     (define count (length v))
     (define-values (ai ext) (argument->ai+ext count))
     ;; Concatenate for the codec (repeated-struct expects flat bytes)
     (define items-concat (apply bytes-append item-bytes))
     (if ext
         (hasheq 'major-type 4 'additional-info ai 'ext-arg ext 'items items-concat)
         (hasheq 'major-type 4 'additional-info ai 'items items-concat))]
    ;; Hash → map
    [(hash? v)
     (define entries (hash->list v))
     (define pair-bytes
       (for/list ([entry entries])
         (bytes-append (cbor-wire-item-encode-value (car entry))
                       (cbor-wire-item-encode-value (cdr entry)))))
     (define count (length entries))
     (define-values (ai ext) (argument->ai+ext count))
     (define pairs-concat (apply bytes-append pair-bytes))
     (if ext
         (hasheq 'major-type 5 'additional-info ai 'ext-arg ext 'pairs pairs-concat)
         (hasheq 'major-type 5 'additional-info ai 'pairs pairs-concat))]
    ;; Flonum
    [(flonum? v)
     (define float-bytes (real->floating-point-bytes v 8 #t))
     (define raw-uint (for/fold ([acc 0]) ([b (in-bytes float-bytes)])
                        (+ (* acc 256) b)))
     (hasheq 'major-type 7 'additional-info 27 'ext-arg raw-uint)]
    [else (error 'cbor-racket->fields "cannot encode: ~e" v)]))

;; Convert a wire struct instance to a Racket value.
;; This works on decoded cbor-wire-item instances.
(define (cbor-wire-item->racket v)
  (define mt (cbor-wire-item-major-type v))
  (define ai (cbor-wire-item-additional-info v))
  (define arg (or (cbor-wire-item-ext-arg v) ai))
  (case mt
    [(0) arg]
    [(1) (- -1 arg)]
    [(2) (or (cbor-wire-item-payload v) (bytes))]
    [(3) (bytes->string/utf-8 (or (cbor-wire-item-payload v) (bytes)))]
    [(4) (define items (or (cbor-wire-item-items v) '()))
         (for/list ([item items])
           (cbor-wire-item->racket item))]
    [(5) (define pairs (or (cbor-wire-item-pairs v) '()))
         (let loop ([ps pairs] [acc '()])
           (if (null? ps) (make-immutable-hash (reverse acc))
               (let ([k (cbor-wire-item->racket (first ps))]
                     [val (cbor-wire-item->racket (second ps))])
                 (loop (cddr ps) (cons (cons k val) acc)))))]
    [(6) (define tagged (cbor-wire-item-tagged v))
         (if tagged (cbor-wire-item->racket tagged) #f)]
    [(7) (cond
           [(= ai 20) #f]
           [(= ai 21) #t]
           [(= ai 22) 'null]
           [(= ai 27)
            (define raw arg)
            (define bs (make-bytes 8))
            (for ([i (in-range 8)])
              (bytes-set! bs (- 7 i) (bitwise-and (arithmetic-shift raw (* -8 i)) #xFF)))
            (floating-point-bytes->real bs #t)]
           [else arg])]))

;; The #:decode function for struct/wire: hash → Racket value
;; (This is called by cbor-wire-item-decode-value)
(define (cbor-fields->racket h)
  (define mt (hash-ref h 'major-type))
  (define ai (hash-ref h 'additional-info))
  (define arg (or (hash-ref h 'ext-arg #f) ai))
  (case mt
    [(0) arg]
    [(1) (- -1 arg)]
    [(2) (hash-ref h 'payload (bytes))]
    [(3) (bytes->string/utf-8 (hash-ref h 'payload (bytes)))]
    [(4) ;; Items: raw bytes from codec — decode each item sequentially
         (define raw (hash-ref h 'items #f))
         (define count (or (hash-ref h 'ext-arg #f) ai))
         (if (and raw (bytes? raw) (> count 0))
             (let loop ([n count] [off 0] [acc '()])
               (if (zero? n) (reverse acc)
                   (let ([item (cbor-wire-item-decode raw #:offset off)])
                     (define sz (protocol-desc-total-size-at raw off cbor-wire-item))
                     (loop (sub1 n) (+ off sz) (cons (cbor-wire-item->racket item) acc)))))
             '())]
    [(5) ;; Pairs: raw bytes — decode sequentially as key,val,key,val,...
         (define raw (hash-ref h 'pairs #f))
         (define pair-count (or (hash-ref h 'ext-arg #f) ai))
         (if (and raw (bytes? raw) (> pair-count 0))
             (let loop ([n pair-count] [off 0] [acc '()])
               (if (zero? n) (make-immutable-hash (reverse acc))
                   (let* ([k (cbor-wire-item-decode raw #:offset off)]
                          [k-sz (protocol-desc-total-size-at raw off cbor-wire-item)]
                          [v (cbor-wire-item-decode raw #:offset (+ off k-sz))]
                          [v-sz (protocol-desc-total-size-at raw (+ off k-sz) cbor-wire-item)])
                     (loop (sub1 n) (+ off k-sz v-sz)
                           (cons (cons (cbor-wire-item->racket k)
                                       (cbor-wire-item->racket v)) acc)))))
             (make-immutable-hash))]
    [(6) ;; Tagged: raw bytes — decode the content
         (define raw (hash-ref h 'tagged #f))
         (if (and raw (bytes? raw))
             (cbor-wire-item->racket (cbor-wire-item-decode raw))
             #f)]
    [(7) (cond
           [(= ai 20) #f]
           [(= ai 21) #t]
           [(= ai 22) 'null]
           [(= ai 27)
            (define raw arg)
            (define bs (make-bytes 8))
            (for ([i (in-range 8)])
              (bytes-set! bs (- 7 i) (bitwise-and (arithmetic-shift raw (* -8 i)) #xFF)))
            (floating-point-bytes->real bs #t)]
           [else arg])]))

(struct/wire cbor-wire-item
  #:byte-order big
  #:encode cbor-racket->fields
  #:decode cbor-fields->racket
  (major-type       uint 3 #:unit bits)
  (additional-info  uint 5 #:unit bits)
  ;; Extended argument: depends on additional-info
  (#:case additional-info
    [((λ (v) (<= v 23)))]         ;; argument is inline (= additional-info)
    [(24) (ext-arg uint 1)]        ;; 1-byte argument
    [(25) (ext-arg uint 2)]        ;; 2-byte argument
    [(26) (ext-arg uint 4)]        ;; 4-byte argument
    [(27) (ext-arg uint 8)])       ;; 8-byte argument
  ;; Payload: depends on major-type
  ;; The effective argument is (or ext-arg additional-info)
  (#:case major-type
    [(0)]                          ;; unsigned int — no payload
    [(1)]                          ;; negative int — no payload
    [(2) (payload octets           ;; byte string
           (compute (λ (lk) (or (lk 'ext-arg) (lk 'additional-info)))))]
    [(3) (payload octets           ;; text string (UTF-8 bytes)
           (compute (λ (lk) (or (lk 'ext-arg) (lk 'additional-info)))))]
    [(4) (items cbor-wire-item     ;; array
           #:repeat (compute (λ (lk) (or (lk 'ext-arg) (lk 'additional-info))))
           #:struct)]
    [(5) (pairs cbor-wire-item     ;; map (2 × count items: k1,v1,k2,v2,...)
           #:repeat (compute (λ (lk) (* 2 (or (lk 'ext-arg) (lk 'additional-info)))))
           #:struct)]
    [(6) (tagged cbor-wire-item    ;; tag — one content item
           #:struct)]
    [(7)]))                        ;; simple/float — no payload (value in argument)

;; ============================================================
;; Semantic Encoding API
;;
;; Deduces discriminator values from the data provided.
;; ============================================================

;; Compute additional-info and ext-arg from an argument value.
(define (argument->ai+ext arg)
  (cond
    [(<= arg 23)     (values arg #f)]
    [(<= arg #xFF)   (values 24 arg)]
    [(<= arg #xFFFF) (values 25 arg)]
    [(<= arg #xFFFFFFFF) (values 26 arg)]
    [else            (values 27 arg)]))

(define (encode-head major-type argument)
  (define-values (ai ext) (argument->ai+ext argument))
  (if ext
      (cbor-wire-item-encode #:major-type major-type #:additional-info ai #:ext-arg ext)
      (cbor-wire-item-encode #:major-type major-type #:additional-info ai)))

(define (cbor-wire-encode-unsigned n)
  (encode-head 0 n))

(define (cbor-wire-encode-negative n)
  ;; n is the actual negative integer; CBOR stores -1-n as the argument
  (encode-head 1 (- -1 n)))

(define (cbor-wire-encode-bytes bs)
  (define-values (ai ext) (argument->ai+ext (bytes-length bs)))
  (if ext
      (cbor-wire-item-encode #:major-type 2 #:additional-info ai #:ext-arg ext #:payload bs)
      (cbor-wire-item-encode #:major-type 2 #:additional-info ai #:payload bs)))

(define (cbor-wire-encode-text str)
  (define utf8 (string->bytes/utf-8 str))
  (define-values (ai ext) (argument->ai+ext (bytes-length utf8)))
  (if ext
      (cbor-wire-item-encode #:major-type 3 #:additional-info ai #:ext-arg ext #:payload utf8)
      (cbor-wire-item-encode #:major-type 3 #:additional-info ai #:payload utf8)))

(define (cbor-wire-encode-array item-bytes-list)
  (define count (length item-bytes-list))
  (define-values (ai ext) (argument->ai+ext count))
  (if ext
      (cbor-wire-item-encode #:major-type 4 #:additional-info ai #:ext-arg ext
                             #:items item-bytes-list)
      (cbor-wire-item-encode #:major-type 4 #:additional-info ai
                             #:items item-bytes-list)))

(define (cbor-wire-encode-map entry-bytes-list)
  ;; entry-bytes-list is a flat list of key-bytes, value-bytes, key-bytes, value-bytes...
  (define pair-count (quotient (length entry-bytes-list) 2))
  (define-values (ai ext) (argument->ai+ext pair-count))
  (if ext
      (cbor-wire-item-encode #:major-type 5 #:additional-info ai #:ext-arg ext
                             #:pairs entry-bytes-list)
      (cbor-wire-item-encode #:major-type 5 #:additional-info ai
                             #:pairs entry-bytes-list)))

(define (cbor-wire-encode-tag tag-number content-bytes)
  (define-values (ai ext) (argument->ai+ext tag-number))
  (if ext
      (cbor-wire-item-encode #:major-type 6 #:additional-info ai #:ext-arg ext
                             #:tagged content-bytes)
      (cbor-wire-item-encode #:major-type 6 #:additional-info ai
                             #:tagged content-bytes)))

(define (cbor-wire-encode-simple sv)
  (if (<= sv 23)
      (cbor-wire-item-encode #:major-type 7 #:additional-info sv)
      (cbor-wire-item-encode #:major-type 7 #:additional-info 24 #:ext-arg sv)))

(define (cbor-wire-encode-float fv)
  ;; IEEE 754 double-precision: 8 bytes big-endian
  ;; We store the raw bytes as a uint64 in ext-arg
  (define float-bytes (real->floating-point-bytes fv 8 #t))
  (define raw-uint (for/fold ([acc 0]) ([b (in-bytes float-bytes)])
                     (+ (* acc 256) b)))
  (cbor-wire-item-encode #:major-type 7 #:additional-info 27 #:ext-arg raw-uint))
