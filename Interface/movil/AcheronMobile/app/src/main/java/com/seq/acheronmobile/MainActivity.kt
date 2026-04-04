package com.seq.acheronmobile

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.navigation.compose.rememberNavController
import com.seq.acheronmobile.data.repository.AuthRepository
import com.seq.acheronmobile.data.repository.TokenRepository
import com.seq.acheronmobile.navigation.AcheronNavGraph
import com.seq.acheronmobile.ui.login.LoginViewModel
import com.seq.acheronmobile.ui.theme.AcheronMobileTheme

class MainActivity : ComponentActivity() {

    // Factory manual — sin Hilt, instanciamos el grafo de dependencias aquí
    private val loginViewModel: LoginViewModel by lazy {
        val tokenRepo = TokenRepository(applicationContext)
        val authRepo  = AuthRepository(tokenRepo)
        ViewModelProvider(this, object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T =
                LoginViewModel(authRepo) as T
        })[LoginViewModel::class.java]
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            AcheronMobileTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val navController = rememberNavController()
                    AcheronNavGraph(
                        navController  = navController,
                        loginViewModel = loginViewModel
                    )
                }
            }
        }
    }
}