package dev.dwarpal.engine;

import dev.dwarpal.crypto.KeyRing;
import dev.dwarpal.decision.CostModel;
import dev.dwarpal.decision.Decision;
import dev.dwarpal.decision.Outcome;
import dev.dwarpal.domain.AccessRequest;
import dev.dwarpal.pip.AttributeDirectory;
import dev.dwarpal.policy.PolicyLinter;
import dev.dwarpal.policy.PolicySet;
import dev.dwarpal.risk.BayesianRiskAggregator;
import dev.dwarpal.risk.RiskAssessment;
import dev.dwarpal.risk.RiskScorer;
import dev.dwarpal.risk.SignalSnapshot;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * The Policy Engine (PE) of NIST SP 800-207: given a request and a signal snapshot, it returns
 * an explained {@link Decision}. Carrying the decision out (sessions, tokens, revocation) is the
 * Policy Administrator's job, not this class's.
 *
 * <p>Pipeline (Chain of Responsibility):
 * evidence verification -> hard gates -> attribute resolution -> risk -> policy -> step-up resolution
 * -> obligations.
 *
 * <p>Properties:
 * <ul>
 *   <li><b>Pure and deterministic</b>: no I/O; same inputs give the same decision (the optional
 *       {@link FreshnessGate} is the only clock reader).</li>
 *   <li><b>Immutable</b>: safe to share across threads. A policy change produces a new engine
 *       via {@link #withPolicySet}.</li>
 *   <li><b>Fail-closed</b>: an unexpected error in any stage yields DENY; {@code decide} does
 *       not throw for runtime failures. Null arguments are programming errors and do throw.</li>
 *   <li><b>Monotonic</b>: stages can only make the outcome stricter; the one exception is a
 *       STEP_UP already satisfied by verified, fresh authentication.</li>
 *   <li><b>Zero trust in the request</b>: attributes come from the directory, posture and
 *       authentication only count when signed by keys in the {@link KeyRing}.</li>
 *   <li><b>Lint-gated</b>: a policy set with linter ERRORs cannot be installed, whether it came
 *       from a file or was built in code.</li>
 * </ul>
 */
public final class PolicyEngine implements DecisionPoint {

    private final PolicySet policySet;
    private final AttributeDirectory directory;
    private final KeyRing keyRing;
    private final AssuranceSettings assurance;
    private final List<HardGate> gates;
    private final List<RiskScorer> scorers;
    private final BayesianRiskAggregator aggregator;
    private final CostModel costModel;
    private final List<DecisionStage> pipeline;

    private PolicyEngine(Builder b) {
        this.policySet = Objects.requireNonNull(b.policySet, "policySet");
        this.directory = Objects.requireNonNull(b.directory, "directory (attributes must never come from the request)");
        this.keyRing = Objects.requireNonNull(b.keyRing, "keyRing (signed evidence needs a trust anchor; use KeyRing.empty() to trust none)");
        this.assurance = Objects.requireNonNull(b.assurance, "assurance");
        double challengeBeta = assurance.bypass(assurance.challengeMethod());
        if (Math.abs(costModel(b).stepUpBypassProbability() - challengeBeta) > 1e-9) {
            // Two sources of truth for "how strong is our MFA" would silently disagree.
            throw new IllegalArgumentException("cost model assumes step-up beta "
                    + costModel(b).stepUpBypassProbability() + " but the challenge method "
                    + assurance.challengeMethod() + " has beta " + challengeBeta);
        }
        this.gates = List.copyOf(b.gates);
        this.scorers = List.copyOf(b.scorers);
        this.aggregator = Objects.requireNonNull(b.aggregator, "aggregator");
        this.costModel = Objects.requireNonNull(b.costModel, "costModel");
        List<PolicyLinter.Finding> errors = new PolicyLinter().lint(policySet).stream()
                .filter(f -> f.severity() == PolicyLinter.Severity.ERROR).toList();
        if (!errors.isEmpty()) {
            throw new IllegalArgumentException("policy set has linter errors: " + errors);
        }
        this.pipeline = List.of(
                new EvidenceVerificationStage(keyRing, assurance),
                new HardGateStage(gates),
                new AttributeResolutionStage(directory),
                new RiskStage(scorers, aggregator, costModel),
                new PolicyStage(policySet),
                new StepUpResolutionStage(assurance, costModel),
                new ObligationStage());
    }

    private static CostModel costModel(Builder b) {
        return Objects.requireNonNull(b.costModel, "costModel");
    }

    public static Builder builder() {
        return new Builder();
    }

    public PolicySet policySet() {
        return policySet;
    }

    public CostModel costModel() {
        return costModel;
    }

    @Override
    public Decision decide(AccessRequest request, SignalSnapshot signals) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(signals, "signals");
        DecisionContext ctx = new DecisionContext(request, signals,
                RiskAssessment.notEvaluated(aggregator.priorAttack()));
        for (DecisionStage stage : pipeline) {
            if (ctx.terminated()) {
                break;
            }
            try {
                stage.apply(ctx);
            } catch (RuntimeException | StackOverflowError e) {
                // StackOverflowError is caught deliberately: a pathological condition tree must
                // become a DENY, not an exception a careless PEP might treat as "allow".
                ctx.terminate(Outcome.DENY, "engine-error",
                        "internal error in stage '" + stage.name() + "' (" + e.getClass().getSimpleName()
                                + "); failing closed");
            }
        }
        return new Decision(request.requestId(), ctx.outcome(), ctx.restricted(), ctx.deviceVerified(),
                ctx.matchedPolicyId(),
                policySet.version(), ctx.risk(), ctx.reasons(), request.timestamp());
    }

    /** A copy of this engine running a different policy set (hot reload, What-If replay). */
    public PolicyEngine withPolicySet(PolicySet newSet) {
        return toBuilder().policySet(newSet).build();
    }

    /** A copy of this engine reading attributes from a different directory. */
    public PolicyEngine withDirectory(AttributeDirectory newDirectory) {
        return toBuilder().directory(newDirectory).build();
    }

    private Builder toBuilder() {
        return builder().policySet(policySet).directory(directory).keyRing(keyRing).assurance(assurance)
                .gates(gates).scorers(scorers).aggregator(aggregator).costModel(costModel);
    }

    public static final class Builder {
        private PolicySet policySet;
        private AttributeDirectory directory;
        private KeyRing keyRing;
        private AssuranceSettings assurance = AssuranceSettings.defaults();
        private final List<HardGate> gates = new ArrayList<>();
        private final List<RiskScorer> scorers = new ArrayList<>();
        private BayesianRiskAggregator aggregator;
        private CostModel costModel;

        private Builder() {
        }

        public Builder policySet(PolicySet set) {
            this.policySet = set;
            return this;
        }

        public Builder directory(AttributeDirectory d) {
            this.directory = d;
            return this;
        }

        public Builder keyRing(KeyRing k) {
            this.keyRing = k;
            return this;
        }

        public Builder assurance(AssuranceSettings a) {
            this.assurance = a;
            return this;
        }

        public Builder gate(HardGate gate) {
            gates.add(Objects.requireNonNull(gate));
            return this;
        }

        public Builder gates(List<HardGate> all) {
            all.forEach(this::gate);
            return this;
        }

        public Builder scorer(RiskScorer scorer) {
            scorers.add(Objects.requireNonNull(scorer));
            return this;
        }

        public Builder scorers(List<RiskScorer> all) {
            all.forEach(this::scorer);
            return this;
        }

        public Builder aggregator(BayesianRiskAggregator a) {
            this.aggregator = a;
            return this;
        }

        public Builder costModel(CostModel c) {
            this.costModel = c;
            return this;
        }

        public PolicyEngine build() {
            return new PolicyEngine(this);
        }
    }
}
