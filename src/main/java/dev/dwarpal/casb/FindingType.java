package dev.dwarpal.casb;

/** The kinds of sensitive data the detectors look for. */
public enum FindingType {
    /** Payment card number: 13 to 19 digits, a known industry prefix, valid Luhn checksum. */
    CARD_NUMBER,
    /** Aadhaar number: 12 digits, first digit 2 to 9, valid Verhoeff checksum. */
    AADHAAR,
    /** Indian Permanent Account Number: 5 letters (4th the holder type), 4 digits, 1 letter. */
    PAN,
    /** Indian Financial System Code: 4 letters, a zero, 6 letters or digits. */
    IFSC,
    /** An e-mail address. */
    EMAIL,
    /** A PEM or PGP private key block. */
    PRIVATE_KEY,
    /** An AWS access key id. */
    AWS_ACCESS_KEY,
    /** A GitHub token (classic or fine-grained). */
    GITHUB_TOKEN,
    /** A Slack token. */
    SLACK_TOKEN
}
