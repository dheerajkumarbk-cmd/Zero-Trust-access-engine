package dev.dwarpal.behavior;

/** Login attributes whose novelty is tracked per user, from most to least specific for the network. */
public enum Feature {
    IP,
    ASN,
    COUNTRY,
    DEVICE
}
