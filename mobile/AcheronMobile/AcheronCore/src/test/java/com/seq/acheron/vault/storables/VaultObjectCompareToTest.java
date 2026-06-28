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

        @Override
        public String category() {
            return "concretevaultobjects";
        }
    }

    // ─── 1. Same reference ───────────────────────────────────────────────────
    @Test
    @DisplayName("compareTo(self) must return 0")
    void compareTo_sameReference_returnsZero() {
        ConcreteVaultObject obj = new ConcreteVaultObject("ACC0", false);
        assertEquals(0, obj.compareTo(obj));
    }

    // ─── 2. Identical IDs ────────────────────────────────────────────────────
    @Test
    @DisplayName("Two objects with the same ID return 0")
    void compareTo_identicalIds_returnsZero() {
        ConcreteVaultObject obj1 = new ConcreteVaultObject("ACC0", false);
        ConcreteVaultObject obj2 = new ConcreteVaultObject("ACC0", false);

        assertEquals("ACC0", obj1.getId());
        assertEquals("ACC0", obj2.getId());
        assertEquals(0, obj1.compareTo(obj2));
    }

    // ─── 3. Smaller prefix → negative result ─────────────────────────────────
    @Test
    @DisplayName("compareTo returns negative when this prefix < other prefix")
    void compareTo_thisPrefixLessThanOther_returnsNegative() {
        ConcreteVaultObject acc = new ConcreteVaultObject("ACC0", false);
        ConcreteVaultObject cdc = new ConcreteVaultObject("CDC0", false);

        assertTrue(acc.compareTo(cdc) < 0, "ACC should come before CDC");
    }

    // ─── 4. Greater prefix → positive result ─────────────────────────────────
    @Test
    @DisplayName("compareTo returns positive when this prefix > other prefix")
    void compareTo_thisPrefixGreaterThanOther_returnsPositive() {
        ConcreteVaultObject acc = new ConcreteVaultObject("ACC0", false);
        ConcreteVaultObject cdc = new ConcreteVaultObject("CDC0", false);

        assertTrue(cdc.compareTo(acc) > 0, "CDC should come after ACC");
    }

    // ─── 5. Same prefix, different number ─────────────────────────────────────
    @Test
    @DisplayName("Same prefix with a different number must NOT return 0")
    void compareTo_samePrefixDifferentCounter_returnsNonZero() {
        ConcreteVaultObject first  = new ConcreteVaultObject("ACC0", false);
        ConcreteVaultObject second = new ConcreteVaultObject("ACC1", false);

        assertNotEquals(0, first.compareTo(second),
                "ACC0 and ACC1 share a prefix but differ in number.");
    }

    // ─── 6. Antisymmetry ─────────────────────────────────────────────────────
    @Test
    @DisplayName("compareTo is antisymmetric: signum(a.compareTo(b)) == -signum(b.compareTo(a))")
    void compareTo_isAntisymmetric() {
        ConcreteVaultObject acc = new ConcreteVaultObject("ACC0", false);
        ConcreteVaultObject cdc = new ConcreteVaultObject("CDC0", false);

        int ab = acc.compareTo(cdc);
        int ba = cdc.compareTo(acc);

        assertEquals(Integer.signum(ab), -Integer.signum(ba),
                "compareTo must be antisymmetric");
    }

    // ─── 7. Ordering in a TreeSet ─────────────────────────────────────────────
    @Test
    @DisplayName("A TreeSet sorts VaultObjects alphabetically by prefix")
    void compareTo_treeSetSorting_sortsByPrefixAlphabetically() {
        ConcreteVaultObject acc = new ConcreteVaultObject("ACC0", false);
        ConcreteVaultObject bcc = new ConcreteVaultObject("BCC0", false);
        ConcreteVaultObject cdc = new ConcreteVaultObject("CDC0", false);

        TreeSet<VaultObject> sorted = new TreeSet<>();
        sorted.add(cdc);
        sorted.add(bcc);
        sorted.add(acc);

        List<VaultObject> list = new ArrayList<>(sorted);
        assertEquals(acc, list.get(0), "ACC must be first");
        assertEquals(bcc, list.get(1), "BCC must be second");
        assertEquals(cdc, list.get(2), "CDC must be last");
    }

    // ─── 8. Numeric comparison of IDs ────────────────────────────────────────
    @Test
    @DisplayName("Numbers in IDs are compared numerically")
    void compareTo_numbers_comparedNumerically() {
        ConcreteVaultObject acc9  = new ConcreteVaultObject("ACC9", false);
        ConcreteVaultObject acc10 = new ConcreteVaultObject("ACC10", false);

        assertEquals("ACC9",  acc9.getId());
        assertEquals("ACC10", acc10.getId());

        assertTrue(acc9.compareTo(acc10) < 0,
                "ACC9 must be less than ACC10 numerically");
    }
}
