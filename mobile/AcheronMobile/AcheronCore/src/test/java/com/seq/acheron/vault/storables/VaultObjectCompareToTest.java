package com.seq.acheron.vault.storables;

import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.vault.interfaces.Storable;
import org.junit.jupiter.api.*;

import java.security.PublicKey;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

public class VaultObjectCompareToTest {

    static class ConcreteVaultObject extends VaultObject {
        public ConcreteVaultObject(String id, boolean isEncrypted) {
            super(id, "ATitle", isEncrypted, false);
        }

        @Override
        String transform(VaultEncryptingStrategy encryptor, boolean encrypt) {
            return this.toString();
        }

        @Override
        public Storable copy() {
            return new ConcreteVaultObject(this.getId(), this.isEncrypted());
        }

        @Override
        public boolean share(PublicKey publicKey, VaultEncryptingStrategy vaultEncryptingStrategy) {
            return false;
        }

        @Override
        public String toJson() {
            return "";
        }
    }

    @BeforeEach
    void noOp() {
        // Counter is per-vault now — no global reset needed
    }

    // ─── 1. Misma referencia ─────────────────────────────────────────────────
    @Test
    @DisplayName("compareTo(self) debe devolver 0")
    void compareTo_sameReference_returnsZero() {
        ConcreteVaultObject obj = new ConcreteVaultObject("ACC0", false);
        assertEquals(0, obj.compareTo(obj));
    }

    // ─── 2. IDs idénticos ────────────────────────────────────────────────────
    @Test
    @DisplayName("Dos objetos con el mismo ID devuelven 0")
    void compareTo_identicalIds_returnsZero() {
        ConcreteVaultObject obj1 = new ConcreteVaultObject("ACC0", false);
        ConcreteVaultObject obj2 = new ConcreteVaultObject("ACC0", false);

        assertEquals("ACC0", obj1.getId());
        assertEquals("ACC0", obj2.getId());
        assertEquals(0, obj1.compareTo(obj2));
    }

    // ─── 3. Prefijo menor → resultado negativo ───────────────────────────────
    @Test
    @DisplayName("compareTo devuelve negativo cuando el prefijo propio < prefijo ajeno")
    void compareTo_thisPrefixLessThanOther_returnsNegative() {
        ConcreteVaultObject acc = new ConcreteVaultObject("ACC0", false);
        ConcreteVaultObject cdc = new ConcreteVaultObject("CDC0", false);

        assertTrue(acc.compareTo(cdc) < 0, "ACC debería ser anterior a CDC");
    }

    // ─── 4. Prefijo mayor → resultado positivo ───────────────────────────────
    @Test
    @DisplayName("compareTo devuelve positivo cuando el prefijo propio > prefijo ajeno")
    void compareTo_thisPrefixGreaterThanOther_returnsPositive() {
        ConcreteVaultObject acc = new ConcreteVaultObject("ACC0", false);
        ConcreteVaultObject cdc = new ConcreteVaultObject("CDC0", false);

        assertTrue(cdc.compareTo(acc) > 0, "CDC debería ser posterior a ACC");
    }

    // ─── 5. Mismo prefijo, número distinto ───────────────────────────────────
    @Test
    @DisplayName("Mismo prefijo con número distinto NO debe devolver 0")
    void compareTo_samePrefixDifferentCounter_returnsNonZero() {
        ConcreteVaultObject first  = new ConcreteVaultObject("ACC0", false);
        ConcreteVaultObject second = new ConcreteVaultObject("ACC1", false);

        assertNotEquals(0, first.compareTo(second),
                "ACC0 y ACC1 comparten prefijo pero difieren en número.");
    }

    // ─── 6. Antisimetría ─────────────────────────────────────────────────────
    @Test
    @DisplayName("compareTo es antisimétrico: signo(a.compareTo(b)) == -signo(b.compareTo(a))")
    void compareTo_isAntisymmetric() {
        ConcreteVaultObject acc = new ConcreteVaultObject("ACC0", false);
        ConcreteVaultObject cdc = new ConcreteVaultObject("CDC0", false);

        int ab = acc.compareTo(cdc);
        int ba = cdc.compareTo(acc);

        assertEquals(Integer.signum(ab), -Integer.signum(ba),
                "compareTo debe ser antisimétrico");
    }

    // ─── 7. Ordenación en TreeSet ─────────────────────────────────────────────
    @Test
    @DisplayName("Un TreeSet ordena VaultObjects alfabéticamente por prefijo")
    void compareTo_treeSetSorting_sortsByPrefixAlphabetically() {
        ConcreteVaultObject acc = new ConcreteVaultObject("ACC0", false);
        ConcreteVaultObject bcc = new ConcreteVaultObject("BCC0", false);
        ConcreteVaultObject cdc = new ConcreteVaultObject("CDC0", false);

        TreeSet<VaultObject> sorted = new TreeSet<>();
        sorted.add(cdc);
        sorted.add(bcc);
        sorted.add(acc);

        List<VaultObject> list = new ArrayList<>(sorted);
        assertEquals(acc, list.get(0), "ACC debe ser el primero");
        assertEquals(bcc, list.get(1), "BCC debe ser el segundo");
        assertEquals(cdc, list.get(2), "CDC debe ser el último");
    }

    // ─── 8. Comparación de números en IDs ───────────────────────────────────
    @Test
    @DisplayName("Los números en IDs se comparan numéricamente")
    void compareTo_numbers_comparedNumerically() {
        ConcreteVaultObject acc9  = new ConcreteVaultObject("ACC9", false);
        ConcreteVaultObject acc10 = new ConcreteVaultObject("ACC10", false);

        assertEquals("ACC9",  acc9.getId());
        assertEquals("ACC10", acc10.getId());

        assertTrue(acc9.compareTo(acc10) < 0,
                "ACC9 debe ser menor que ACC10 numéricamente");
    }
}
