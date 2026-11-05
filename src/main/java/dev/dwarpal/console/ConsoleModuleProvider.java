package dev.dwarpal.console;

import dev.dwarpal.lab.LabRunner;
import dev.dwarpal.lab.LabWorld;

import java.util.List;

/**
 * How the admin, lab and guide modules (parts I and J) reach the console without {@link ConsoleMain} knowing them:
 * a jar lists its provider in {@code META-INF/services/dev.dwarpal.console.ConsoleModuleProvider} and the launcher
 * loads every provider with {@link java.util.ServiceLoader}. A provider gets the running lab, builds its modules and
 * hands them back; the server then checks role, anti-forgery token and step-up before it calls them.
 */
public interface ConsoleModuleProvider {

    /** The modules this provider adds; {@code runner} may be null in a test that does not run the clock. */
    List<ConsoleModule> modules(LabWorld world, LabRunner runner);
}
