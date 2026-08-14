package io.github.kostack.jwt_security.extensions

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class PayloadExtensionsTest {
  @Test
  fun `getClaim returns claim with requested type`() {
    val claims = mapOf<String, Any>("subject" to "user-123")

    assertEquals("user-123", claims.getClaim<String>("subject"))
  }

  @Test
  fun `getClaim throws when claim is missing`() {
    val exception =
      assertFailsWith<IllegalArgumentException> {
        emptyMap<String, Any>().getClaim<String>("subject")
      }

    assertEquals("subject claim is required but was null", exception.message)
  }

  @Test
  fun `getClaim throws when claim has unexpected type`() {
    val claims = mapOf<String, Any>("expiration" to 123L)

    val exception =
      assertFailsWith<IllegalArgumentException> {
        claims.getClaim<String>("expiration")
      }

    assertEquals("expiration claim expected String but was Long", exception.message)
  }

  @Test
  fun `getClaimOrNull returns claim with requested type`() {
    val claims = mapOf<String, Any>("roles" to listOf("admin", "user"))

    assertEquals(listOf("admin", "user"), claims.getClaimOrNull<List<String>>("roles"))
  }

  @Test
  fun `getClaimOrNull returns null when claim is missing`() {
    assertNull(emptyMap<String, Any>().getClaimOrNull<String>("subject"))
  }

  @Test
  fun `getClaimOrNull throws when claim has unexpected type`() {
    val claims = mapOf<String, Any>("active" to true)

    val exception =
      assertFailsWith<IllegalArgumentException> {
        claims.getClaimOrNull<String>("active")
      }

    assertEquals("active claim expected String but was Boolean", exception.message)
  }
}
