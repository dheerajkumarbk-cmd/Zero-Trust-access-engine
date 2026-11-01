package dev.dwarpal.engine;

/** One link in the decision pipeline (Chain of Responsibility). */
interface DecisionStage {

    String name();

    void apply(DecisionContext context);
}
