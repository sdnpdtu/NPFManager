package eu.ngpaas.pmLib;

import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BiConsumer;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collector;

public class PolicyCollector implements Collector<PolicyRule, CopyOnWriteArrayList<PolicyRule>, CopyOnWriteArrayList<PolicyRule>> {

    @Override
    public Supplier<CopyOnWriteArrayList<PolicyRule>> supplier() {
        return CopyOnWriteArrayList::new;
    }

    @Override
    public BiConsumer<CopyOnWriteArrayList<PolicyRule>, PolicyRule> accumulator() {
        return (pRules, newRule) -> pRules.add(newRule);
    }

    @Override
    public BinaryOperator<CopyOnWriteArrayList<PolicyRule>> combiner() {
        return (pRules1, pRules2) -> {
            pRules2.stream().forEach(rule -> pRules1.add(rule));
            return pRules1;
        };
    }

    @Override
    public Function<CopyOnWriteArrayList<PolicyRule>, CopyOnWriteArrayList<PolicyRule>> finisher() {
        return Function.identity();
    }

    @Override
    public Set<Characteristics> characteristics() {

        return EnumSet.of(Characteristics.UNORDERED, Characteristics.IDENTITY_FINISH);
    }
}

