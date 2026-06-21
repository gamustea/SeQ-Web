package com.seq.acheronmobile

import android.graphics.Color
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.navigation.compose.rememberNavController
import com.seq.acheronmobile.data.network.NetworkModule
import com.seq.acheronmobile.data.repository.AuthRepository
import com.seq.acheronmobile.data.repository.TokenRepository
import com.seq.acheronmobile.data.repository.VaultRemoteDataSource
import com.seq.acheronmobile.data.vault.VaultCryptoService
import com.seq.acheronmobile.di.VaultServiceLocator
import com.seq.acheronmobile.navigation.AcheronNavGraph
import com.seq.acheronmobile.ui.login.LoginViewModel
import com.seq.acheronmobile.ui.theme.AcheronMobileTheme
import com.seq.acheronmobile.ui.vault.VaultViewModel

class MainActivity : ComponentActivity() {

    private val loginViewModel: LoginViewModel by lazy {
        val tokenRepo = TokenRepository(applicationContext)
        val authRepo  = AuthRepository(tokenRepo)
        ViewModelProvider(this, object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T =
                LoginViewModel(authRepo, tokenRepo) as T
        })[LoginViewModel::class.java]
    }

    private val vaultViewModel: VaultViewModel by lazy {
        ViewModelProvider(this)[VaultViewModel::class.java]
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        // Instala la pantalla de inicio de marca (rio purpura sobre el abismo)
        // antes de super.onCreate; sustituye al splash automatico del sistema.
        installSplashScreen()
        super.onCreate(savedInstanceState)
        val tokenRepo = TokenRepository(applicationContext)
        NetworkModule.initialize(tokenRepo)

        // Init vault services (recreated on process death)
        VaultServiceLocator.cryptoService = VaultCryptoService()
        VaultServiceLocator.remoteDataSource = VaultRemoteDataSource()
        // Restaura el username de la sesion activa: necesario para validar el
        // checker del vault si se arranca directamente en MASTER_KEY (ver #3).
        VaultServiceLocator.username = tokenRepo.getUsername() ?: ""

        // La identidad de Acheron es siempre oscura, asi que fijamos iconos de
        // barra claros (estilo "dark") para que no queden invisibles aunque el
        // sistema este en modo claro.
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(Color.TRANSPARENT)
        )
        setContent {
            AcheronMobileTheme(dynamicColor = false) {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val navController = rememberNavController()
                    AcheronNavGraph(
                        navController  = navController,
                        loginViewModel = loginViewModel,
                        vaultViewModel = vaultViewModel
                    )
                }
            }
        }
    }
}
