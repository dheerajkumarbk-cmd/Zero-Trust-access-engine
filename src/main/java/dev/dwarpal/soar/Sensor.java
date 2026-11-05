package dev.dwarpal.soar;

/**
 * The channel to endpoint sensors. Delivering a command proves nothing: the device is counted as isolated only
 * when its sensor sends back a signed acknowledgement ({@link DeviceIsolation#acknowledge}).
 */
@FunctionalInterface
public interface Sensor {

    /** @return false if the command could not be handed over (sensor offline); may throw, which counts as false */
    boolean deliver(IsolationCommand command);
}
