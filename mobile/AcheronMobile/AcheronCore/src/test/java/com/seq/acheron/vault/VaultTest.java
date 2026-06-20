package com.seq.acheron.vault;

import com.seq.acheron.vault.secrets.symmetric.Argon2VaultEncryptingStrategy;
import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategy;
import com.seq.acheron.util.CryptoUtils;
import com.seq.acheron.vault.storables.Account;
import com.seq.acheron.vault.storables.CreditCard;
import com.seq.acheron.vault.interfaces.Storable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Suite de tests nativos JUnit para Vault y VaultFactory")
public class VaultTest {

    private User testUser;
    private VaultEncryptingStrategy testStrategy;

    @BeforeEach
    void setUp() throws GeneralSecurityException {
        // Inicializamos con el objeto User real
        testUser = new User("a", "b", "c", "d", "e");

        // Usamos la estrategia AES real con una contraseña de prueba y un salt generado
        String salt = CryptoUtils.generateSalt();
        testStrategy = new Argon2VaultEncryptingStrategy("MiPassSuperSegura123", salt, true);
    }

    @Nested
    @DisplayName("Tests unitarios de la clase Vault")
    class VaultBasicTests {

        @Test
        @DisplayName("El Vault se inicializa correctamente")
        void testVaultInitialization() throws GeneralSecurityException {
            Vault vault = new Vault(testStrategy, testUser, false);

            assertTrue(vault.getStorables().isEmpty(), "El Vault debe iniciar sin elementos");
            assertFalse(vault.isEncrypted(), "El estado inicial de cifrado debe coincidir con el constructor");
            assertNotNull(vault.getChecker(), "El checker debe haberse computado");
            assertEquals(testUser, vault.getUser(), "El usuario almacenado debe ser el que pasamos por parámetro");
        }

        @Test
        @DisplayName("Operaciones básicas de Storables: add, get y ordenación natural")
        void testAddAndGet() throws GeneralSecurityException {
            Vault vault = new Vault(testStrategy, testUser, false);

            // Creamos implementaciones reales (Account y CreditCard implementan Storable)
            Account account1 = new Account("ZZZ_ID", "Account1", "userZ", "zzz.com", "passZ", false);
            Account account2 = new Account("AAA_ID", "Account2", "userA", "aaa.com", "passA", false);
            CreditCard card = new CreditCard("CARD_ID", "CreditCard", "John", "1234", "12/28", "123", "28001", false);

            // Añadimos en orden desordenado para comprobar si .sort(null) actúa
            vault.add(account1).add(card).add(account2);

            List<Storable> storables = vault.getStorables();
            assertEquals(3, storables.size(), "Debe haber 3 elementos en la lista");

            // Comprobamos la recuperación de elementos
            assertEquals(account1, vault.get("ZZZ_ID"));
            assertEquals(card, vault.get("CARD_ID"));
            assertNull(vault.get("NO_EXISTE"));
        }

        @Test
        @DisplayName("Eliminar Storables funciona correctamente")
        void testRemove() throws GeneralSecurityException {
            Vault vault = new Vault(testStrategy, testUser, false);
            Account acc = new Account("TEST_ID", "usr", "dom", "pass", false);

            vault.add(acc);
            assertEquals(1, vault.getStorables().size());

            vault.remove(acc);
            assertTrue(vault.getStorables().isEmpty(), "Tras el borrado el Vault debe quedar vacío");

            // Comprobar borrados silenciosos (null o inexistentes)
            assertDoesNotThrow(() -> vault.remove(null));
            assertDoesNotThrow(() -> vault.remove(new Account("OTRO", "", "", "", false)));
        }

        @Test
        @DisplayName("El flag isEncrypted lanza IllegalStateException correctamente")
        void testEncryptionStateExceptions() throws GeneralSecurityException {
            Vault vault = new Vault(testStrategy, testUser, false);

            vault.encryptAll();
            assertTrue(vault.isEncrypted());

            // Si está cifrado, no puedo volver a cifrar
            assertThrows(IllegalStateException.class, vault::encryptAll);

            vault.decryptAll();
            assertFalse(vault.isEncrypted());

            // Si está descifrado, no puedo volver a descifrar
            assertThrows(IllegalStateException.class, vault::decryptAll);
        }
    }

    @Nested
    @DisplayName("Tests de Integración (Cifrado real, JSON y VaultFactory)")
    class IntegrationTests {

        @Test
        @DisplayName("El VaultFactory genera el mockVault esperado")
        void testFactoryMockVault() throws GeneralSecurityException {
            VaultFactory factory = new VaultFactory(testUser);
            Vault mockVault = factory.getMockVault();

            assertNotNull(mockVault);
            assertFalse(mockVault.isEncrypted(), "El mockVault debe estar descifrado por defecto");
            assertEquals(5, mockVault.getStorables().size(), "El mockVault inicializa 5 storables de demo");
        }

        @Test
        @DisplayName("El cifrado AES modifica las contraseñas reales")
        void testRealEncryptionTransformsData() throws GeneralSecurityException {
            Vault vault = new Vault(testStrategy, testUser, false);
            Account account = new Account("MY_ACC", "admin", "admin.com", "PlainPassword123", false);
            vault.add(account);

            vault.encryptAll();

            // Evaluamos la integración comprobando que la contraseña ya no es el texto plano
            assertTrue(vault.isEncrypted());
            assertNotEquals("PlainPassword123", account.getPassword(), "El password debe estar cifrado por la AESVaultEncryptingStrategy");
        }

        @Test
        @DisplayName("Ciclo completo de vida: Creación -> Cifrado -> toJSON -> fromJSON -> Descifrado")
        void testVaultFullLifecycle() throws GeneralSecurityException {
            // 1. Configuramos el Factory y obtenemos el vault original
            VaultFactory factory = new VaultFactory(testUser);
            Vault originalVault = factory.getMockVault();

            // 2. Modificamos y añadimos nuestros propios valores al mockVault base
            Account customAcc = new Account("CUSTOM_ID", "Account1", "gabriel", "test.com", "SecretPass!1", false);
            originalVault.add(customAcc);

            // 3. Ciframos toda la bóveda y la convertimos en String
            originalVault.encryptAll();
            String exportedJson = originalVault.toJson();

            assertNotNull(exportedJson);
            assertTrue(exportedJson.contains("\"checker\""), "El JSON debe incluir el checker de contraseña");
            assertTrue(exportedJson.contains("\"CUSTOM_ID\""), "El JSON debe incluir el storable custom");

            // 4. Restauramos la bóveda en un nuevo objeto usando la contraseña de default de mockVault ("CONTRASEÑA")
            Vault restoredVault = factory.fromJson(exportedJson, "Contraseña");

            // 5. Validaciones de la restauración
            assertTrue(restoredVault.isEncrypted(), "Al venir de un fromJSON cifrado, debe estar true");
            assertEquals(originalVault.getStorables().size(), restoredVault.getStorables().size());
            assertEquals(originalVault.getChecker(), restoredVault.getChecker());

            // 6. Desciframos para volver a los valores en plano
            restoredVault.decryptAll();
            assertFalse(restoredVault.isEncrypted());

            // Recuperamos el storable y nos aseguramos que el descifrado real funcionó
            Account restoredCustomAcc = (Account) restoredVault.get("CUSTOM_ID");
            assertEquals("gabriel", restoredCustomAcc.getUsername());
            assertEquals("SecretPass!1", restoredCustomAcc.getPassword(), "El password descifrado debe coincidir exactamente");
        }
    }
}
