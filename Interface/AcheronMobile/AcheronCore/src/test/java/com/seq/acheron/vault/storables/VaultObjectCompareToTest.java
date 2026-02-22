package com.seq.acheron.vault.storables;

import com.seq.acheron.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.vault.interfaces.Storable;
import org.junit.jupiter.api.*;

import java.security.PublicKey;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

public class VaultObjectCompareToTest {

    static class ConcreteVaultObject extends VaultObject {
        public ConcreteVaultObject(String code, boolean isEncrypted) {
            super(code, "ATitle", isEncrypted, true);
        }

        @Override
        String transform(VaultEncryptingStrategy encryptor, boolean encrypt) {
            return this.toString();
        }

        @Override
        public Storable copy() {
            return new ConcreteVaultObject("TEST", this.isEncrypted());
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
    void resetCounter() {
        // El contador estático afecta a todos los IDs generados: hay que reiniciarlo
        VaultObject.setObjectCounter(0);
    }

    // ─── 1. Misma referencia ─────────────────────────────────────────────────
    @Test
    @DisplayName("compareTo(self) debe devolver 0")
    void compareTo_sameReference_returnsZero() {
        ConcreteVaultObject obj = new ConcreteVaultObject("ACC", false); // ID: ACC0
        assertEquals(0, obj.compareTo(obj));
    }

    // ─── 2. IDs idénticos (mismo prefijo + mismo contador) ──────────────────
    @Test
    @DisplayName("Dos objetos con el mismo ID devuelven 0")
    void compareTo_identicalIds_returnsZero() {
        ConcreteVaultObject obj1 = new ConcreteVaultObject("ACC", false); // ID: ACC0
        VaultObject.setObjectCounter(0);
        ConcreteVaultObject obj2 = new ConcreteVaultObject("ACC", false); // ID: ACC0

        assertEquals("ACC0", obj1.getId());
        assertEquals("ACC0", obj2.getId());
        assertEquals(0, obj1.compareTo(obj2));
    }

    // ─── 3. Prefijo menor → resultado negativo ───────────────────────────────
    @Test
    @DisplayName("compareTo devuelve negativo cuando el prefijo propio < prefijo ajeno")
    void compareTo_thisPrefixLessThanOther_returnsNegative() {
        ConcreteVaultObject acc = new ConcreteVaultObject("ACC", false); // ACC0
        ConcreteVaultObject cdc = new ConcreteVaultObject("CDC", false); // CDC1

        assertTrue(acc.compareTo(cdc) < 0, "ACC debería ser anterior a CDC");
    }

    // ─── 4. Prefijo mayor → resultado positivo ───────────────────────────────
    @Test
    @DisplayName("compareTo devuelve positivo cuando el prefijo propio > prefijo ajeno")
    void compareTo_thisPrefixGreaterThanOther_returnsPositive() {
        ConcreteVaultObject acc = new ConcreteVaultObject("ACC", false); // ACC0
        ConcreteVaultObject cdc = new ConcreteVaultObject("CDC", false); // CDC1

        assertTrue(cdc.compareTo(acc) > 0, "CDC debería ser posterior a ACC");
    }

    // ─── 5. Mismo prefijo, número distinto ───────────────────────────────────
    // ⚠️ PUEDE FALLAR si Pair no sobreescribe equals():
    //    new Pair<>(...).equals(new Pair<>(...)) usaría igualdad de referencia,
    //    por lo que !thisCode.equals(otherCode) siempre sería true,
    //    comparando solo la parte izquierda → devuelve 0 erróneamente.
    @Test
    @DisplayName("Mismo prefijo con número distinto NO debe devolver 0")
    void compareTo_samePrefixDifferentCounter_returnsNonZero() {
        ConcreteVaultObject first  = new ConcreteVaultObject("ACC", false); // ACC0
        ConcreteVaultObject second = new ConcreteVaultObject("ACC", false); // ACC1

        assertNotEquals(0, first.compareTo(second),
                "⚠ Fallará si Pair no sobreescribe equals(). " +
                        "ACC0 y ACC1 comparten prefijo pero difieren en número.");
    }

    // ─── 6. Antisimetría ─────────────────────────────────────────────────────
    @Test
    @DisplayName("compareTo es antisimétrico: signo(a.compareTo(b)) == -signo(b.compareTo(a))")
    void compareTo_isAntisymmetric() {
        ConcreteVaultObject acc = new ConcreteVaultObject("ACC", false);
        ConcreteVaultObject cdc = new ConcreteVaultObject("CDC", false);

        int ab = acc.compareTo(cdc);
        int ba = cdc.compareTo(acc);

        assertEquals(Integer.signum(ab), -Integer.signum(ba),
                "compareTo debe ser antisimétrico");
    }

    // ─── 7. Ordenación en TreeSet ─────────────────────────────────────────────
    @Test
    @DisplayName("Un TreeSet ordena VaultObjects alfabéticamente por prefijo")
    void compareTo_treeSetSorting_sortsByPrefixAlphabetically() {
        ConcreteVaultObject acc = new ConcreteVaultObject("ACC", false);
        ConcreteVaultObject bcc = new ConcreteVaultObject("BCC", false);
        ConcreteVaultObject cdc = new ConcreteVaultObject("CDC", false);

        TreeSet<VaultObject> sorted = new TreeSet<>();
        sorted.add(cdc);
        sorted.add(bcc);
        sorted.add(acc);

        List<VaultObject> list = new ArrayList<>(sorted);
        assertEquals(acc, list.get(0), "ACC debe ser el primero");
        assertEquals(bcc, list.get(1), "BCC debe ser el segundo");
        assertEquals(cdc, list.get(2), "CDC debe ser el último");
    }

    // ─── 8. Comparación lexicográfica de números (no numérica) ───────────────
    // ⚠️ "10" < "9" como strings → ACC10 se ordena ANTES que ACC9.
    //    Considera usar Integer.parseInt() si necesitas orden numérico real.
    @Test
    @DisplayName("Los números se comparan lexicográficamente, no numéricamente")
    void compareTo_lexicographicNumbers_documentsBehavior() {
        for (int i = 0; i < 9; i++) new ConcreteVaultObject("ACC", false); // 0..8
        ConcreteVaultObject acc9  = new ConcreteVaultObject("ACC", false); // ACC9
        ConcreteVaultObject acc10 = new ConcreteVaultObject("ACC", false); // ACC10

        assertEquals("ACC9",  acc9.getId());
        assertEquals("ACC10", acc10.getId());

        assertTrue(acc10.compareTo(acc9) > 0,
                "Error al calcular qué número era mayor");
    }
}
