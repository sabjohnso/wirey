#lang scribble/manual

@require[@for-label[racket/base
                    racket/match]]

@title{wirey: Binary Wire Protocol Specifications}
@author{sbj}

@bold{wirey} is a Racket-native DSL for declaratively specifying binary
wire protocols. It describes the wire format; generates encoders,
decoders, accessors, and match expanders from the description.

@table-of-contents[]

@; ------------------------------------------------------------------
@section{Architecture}

wirey has three layers:

@itemlist[#:style 'ordered
  @item{@bold{IR} (@tt{ir.rkt}) — Data structures representing a
    wire protocol's layout: @tt{wire-field}, @tt{wire-bitfield-group},
    @tt{wire-case}, @tt{wire-padding}, @tt{wire-protocol}.}
  @item{@bold{Codec} (@tt{ir-codec.rkt}) — @tt{ir-encode} and
    @tt{ir-decode} walk the element tree to produce bytes or field
    hashes.}
  @item{@bold{Macro} (@tt{syntax2.rkt}) — @tt{struct/wire} parses
    Racket syntax into the IR, then generates encode/decode bindings
    that delegate to the codec.}
]

@; ------------------------------------------------------------------
@section{Quick Start}

@racketblock[
(require wirey/syntax2 racket/match)

(struct/wire udp-header
  #:byte-order big
  (src-port   uint 2)
  (dst-port   uint 2)
  (length     uint 2)
  (checksum   uint 2))

(code:comment "Encode with keyword arguments")
(define pkt
  (udp-header-encode
   #:src-port  49152
   #:dst-port  53
   #:length    42
   #:checksum  0))

(code:comment "Decode to a wire struct, access fields by name")
(define hdr (udp-header-decode pkt))
(udp-header-src-port hdr)
(udp-header-dst-port hdr)

(code:comment "Pattern match on specific fields")
(match hdr
  [(udp-header #:dst-port dp #:src-port sp)
   (printf "~a → ~a\n" sp dp)])
]

@; ------------------------------------------------------------------
@section{Wire Structures}

@defform[(struct/wire name
           maybe-byte-order
           maybe-bit-order
           maybe-alignment
           maybe-encode
           maybe-decode
           field-spec ...)
         #:grammar
         ([maybe-byte-order (code:line)
                            (code:line #:byte-order byte-order-id)]
          [maybe-bit-order (code:line)
                           (code:line #:bit-order bit-order-id)]
          [maybe-alignment (code:line)
                           (code:line #:alignment nat)]
          [maybe-encode (code:line)
                        (code:line #:encode expr)]
          [maybe-decode (code:line)
                        (code:line #:decode expr)]
          [field-spec (field-name type-id width-expr field-option ...)
                      (field-name padding width-or-align)
                      (#:case disc-name branch ...)]
          [branch ((pred-or-value) field-spec ...)]
          [field-option (code:line #:byte-order byte-order-id)
                        (code:line #:unit unit-id)
                        (code:line #:bit-order bit-order-id)
                        (code:line #:compute expr)
                        (code:line #:contract expr)
                        (code:line #:present-when expr)
                        (code:line #:default expr)
                        (code:line #:enum expr)
                        (code:line #:terminator nat)
                        (code:line #:repeat expr)
                        (code:line #:repeat-until expr)])]{

Defines a binary wire structure and introduces:

@itemlist[
  @item{@racketvarfont{name} — a @tt{wire-protocol} value (also a
    @racket[match] expander)}
  @item{@racketvarfont{name}@racketidfont{?} — predicate}
  @item{@racketvarfont{name}@racketidfont{-encode} — keyword args → @racket[bytes]}
  @item{@racketvarfont{name}@racketidfont{-decode} — @racket[bytes] → wire struct instance}
  @item{@racketvarfont{name}@racketidfont{-}@racketvarfont{field} — accessor per
    non-padding field}
  @item{@racketvarfont{name}@racketidfont{-encode-value} — Racket value → @racket[bytes]
    (when @racket[#:encode] provided)}
  @item{@racketvarfont{name}@racketidfont{-decode-value} — @racket[bytes] → Racket value
    (when @racket[#:decode] provided)}
]}

@subsection{Field Types}

@tabular[#:style 'boxed
         #:column-properties '(left left left)
         (list (list @bold{Type} @bold{Width} @bold{Description})
               (list @racket[uint] "N bytes" "Unsigned integer")
               (list @racket[sint] "N bytes" "Signed two's complement")
               (list @racket[alpha] "N bytes" "ASCII, space-padded")
               (list @racket[octets] "N bytes" "Raw bytes")
               (list @racket[float32] "4 bytes" "IEEE 754 single-precision")
               (list @racket[float64] "8 bytes" "IEEE 754 double-precision")
               (list @racket[bool] "1 byte"  "Boolean: 0 = #f, nonzero = #t")
               (list @racket[utf8] "N bytes" "UTF-8 string, null-padded")
               (list @racket[padding] "N bytes" "Zero bytes, skipped on decode"))]

@subsection{Bitfields}

Fields with @racket[#:unit bits] form groups packed into bytes:

@racketblock[
(struct/wire ipv4-header
  #:byte-order big
  (version          uint 4  #:unit bits)
  (ihl              uint 4  #:unit bits)
  (dscp             uint 6  #:unit bits)
  (ecn              uint 2  #:unit bits)
  (total-length     uint 2)
  ...)
]

@subsection{Case Dispatch}

@racket[#:case] selects different field layouts based on a field value:

@racketblock[
(struct/wire tagged-msg
  #:byte-order big
  (tag uint 1)
  (#:case tag
    [(1) (val uint 1)]
    [(2) (val uint 2)]
    [((λ (v) (> v 10))) (data octets (field-ref tag))]))
]

Branches can contain variable-length fields, nested cases, and any
field type. Case branch fields become optional keyword args on encode
(default @racket[#f]).

@subsection{Variable-Length Fields}

@racketblock[
(struct/wire length-prefixed
  #:byte-order big
  (len  uint 2)
  (data octets (field-ref len)))
]

@racket[(compute (λ (lk) expr))] for computed widths:

@racketblock[
(payload octets (compute (λ (lk) (or (lk 'ext-arg) (lk 'info)))))
]

@subsection{Value-Level Encode/Decode}

For self-describing formats, @racket[#:encode] and @racket[#:decode]
map between Racket values and field hashes:

@racketblock[
(struct/wire cbor-item
  #:byte-order big
  #:encode cbor-racket->fields
  #:decode cbor-fields->racket
  (major-type       uint 3 #:unit bits)
  (additional-info  uint 5 #:unit bits)
  (#:case additional-info
    [((λ (v) (<= v 23)))]
    [(24) (ext-arg uint 1)]
    [(25) (ext-arg uint 2)]
    ...)
  (#:case major-type
    [(0)] [(1)]
    [(2) (payload octets (compute ...))]
    ...))

(cbor-item-encode-value 42)
(cbor-item-decode-value (bytes #x18 #x2A))
]

@; ------------------------------------------------------------------
@section{Scope}

wirey aims to be a complete specification language for binary wire
formats. Anything implementable with ASN.1 + ACN should be
implementable with wirey.

Verified targets:
@itemlist[
  @item{CBOR (RFC 8949) — self-describing, recursive}
  @item{MessagePack — self-describing, recursive}
  @item{BSON — length-prefixed, type-tagged}
  @item{ITCH 5.0 — fixed-layout, full network stack}
]
