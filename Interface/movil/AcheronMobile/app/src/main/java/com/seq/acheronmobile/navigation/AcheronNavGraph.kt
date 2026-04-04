package com.seq.acheronmobile.navigation

import androidx.compose.runtime.Composable
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import com.seq.acheronmobile.ui.login.LoginScreen
import com.seq.acheronmobile.ui.login.LoginViewModel
import com.seq.acheronmobile.ui.vault.MasterKeyScreen

object Routes {
    const val LOGIN      = "login"
    const val MASTER_KEY = "master_key"
}

@Composable
fun AcheronNavGraph(
    navController: NavHostController,
    loginViewModel: LoginViewModel
) {
    NavHost(
        navController = navController,
        startDestination = Routes.LOGIN
    ) {
        composable(Routes.LOGIN) {
            LoginScreen(
                viewModel = loginViewModel,
                onLoginSuccess = {
                    navController.navigate(Routes.MASTER_KEY) {
                        popUpTo(Routes.LOGIN) { inclusive = true }
                    }
                }
            )
        }

        composable(Routes.MASTER_KEY) {
            MasterKeyScreen()
        }
    }
}