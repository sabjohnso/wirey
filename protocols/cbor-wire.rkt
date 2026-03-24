#lang racket/base

;; ============================================================
;; CBOR Wire Structure (RFC 8949)
;;
;; Definite-length CBOR items expressed via struct/wire.
;; This proves wirey's DSL can describe self-describing recursive
;; formats. Indefinite-length encoding is handled by a thin
;; wrapper that reuses this definition.
;; ============================================================

(require wirey/syntax
         wirey/protocol
         wirey/codec)

(provide (all-defined-out)
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
(struct/wire cbor-wire-item
  #:byte-order big
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
