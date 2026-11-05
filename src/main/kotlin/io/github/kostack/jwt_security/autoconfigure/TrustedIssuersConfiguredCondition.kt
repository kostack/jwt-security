package io.github.kostack.jwt_security.autoconfigure

import org.springframework.boot.autoconfigure.condition.ConditionOutcome
import org.springframework.boot.autoconfigure.condition.SpringBootCondition
import org.springframework.boot.context.properties.bind.Bindable
import org.springframework.boot.context.properties.bind.Binder
import org.springframework.context.annotation.ConditionContext
import org.springframework.core.type.AnnotatedTypeMetadata

internal class TrustedIssuersConfiguredCondition : SpringBootCondition() {
  override fun getMatchOutcome(
    context: ConditionContext,
    metadata: AnnotatedTypeMetadata
  ): ConditionOutcome {
    val issuers =
      Binder
        .get(context.environment)
        .bind(
          "kostack-security.trusted-issuers",
          Bindable.mapOf(String::class.java, SecurityProperties.TrustedIssuer::class.java)
        ).orElse(emptyMap())
        .orEmpty()
    return ConditionOutcome(
      issuers.isNotEmpty(),
      "Trusted issuers are ${if (issuers.isEmpty()) "not " else ""}configured"
    )
  }
}
