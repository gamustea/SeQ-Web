package com.seq.acheronmobile.navigation

import androidx.compose.runtime.Composable
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.seq.acheronmobile.data.vault.StorableUi
import com.seq.acheronmobile.ui.login.LoginScreen
import com.seq.acheronmobile.ui.login.LoginViewModel
import com.seq.acheronmobile.ui.vault.MasterKeyScreen
import com.seq.acheronmobile.ui.vault.MasterKeyViewModel
import com.seq.acheronmobile.ui.vault.StorableDetailScreen
import com.seq.acheronmobile.ui.vault.StorableFormScreen
import com.seq.acheronmobile.ui.vault.VaultListScreen
import com.seq.acheronmobile.ui.vault.VaultViewModel

object Routes {
    const val LOGIN      = "login"
    const val MASTER_KEY = "master_key"
    const val VAULT_LIST = "vault_list"
    const val STORABLE_DETAIL = "storable_detail/{id}"
    const val STORABLE_ADD = "storable_add/{kind}"
    const val STORABLE_EDIT = "storable_edit/{id}"
}

@Composable
fun AcheronNavGraph(
    navController: NavHostController,
    loginViewModel: LoginViewModel,
    vaultViewModel: VaultViewModel
) {
    val startDestination = if (loginViewModel.hasActiveSession)
        Routes.MASTER_KEY
    else
        Routes.LOGIN

    val onLogout: () -> Unit = {
        loginViewModel.logout()
        navController.navigate(Routes.LOGIN) {
            popUpTo(0) { inclusive = true }
        }
    }

    NavHost(
        navController    = navController,
        startDestination = startDestination
    ) {
        composable(Routes.LOGIN) {
            LoginScreen(
                viewModel    = loginViewModel,
                onLoginSuccess = {
                    navController.navigate(Routes.MASTER_KEY) {
                        popUpTo(Routes.LOGIN) { inclusive = true }
                    }
                }
            )
        }

        composable(Routes.MASTER_KEY) {
            val masterKeyVM: MasterKeyViewModel = viewModel()
            MasterKeyScreen(
                viewModel = masterKeyVM,
                onVaultUnlocked = {
                    navController.navigate(Routes.VAULT_LIST) {
                        popUpTo(Routes.MASTER_KEY) { inclusive = true }
                    }
                },
                onLogout = onLogout
            )
        }

        composable(Routes.VAULT_LIST) {
            VaultListScreen(
                viewModel = vaultViewModel,
                onAdd = { kind ->
                    navController.navigate("storable_add/$kind")
                },
                onStorableClick = { storable ->
                    navController.navigate("storable_detail/${storable.id}")
                },
                onLock = {
                    navController.navigate(Routes.MASTER_KEY) {
                        popUpTo(0) { inclusive = true }
                    }
                },
                onLogout = onLogout
            )
        }

        composable(
            route = Routes.STORABLE_DETAIL,
            arguments = listOf(navArgument("id") { type = NavType.StringType })
        ) { backStackEntry ->
            val id = backStackEntry.arguments?.getString("id") ?: return@composable
            val storable = vaultViewModel.uiState.value.storables.find { it.id == id }
            if (storable != null) {
                StorableDetailScreen(
                    storable = storable,
                    vaultViewModel = vaultViewModel,
                    onBack = { navController.popBackStack() },
                    onDeleted = { navController.popBackStack() }
                )
            }
        }

        composable(
            route = Routes.STORABLE_ADD,
            arguments = listOf(navArgument("kind") { type = NavType.StringType })
        ) { backStackEntry ->
            val kind = backStackEntry.arguments?.getString("kind") ?: "account"
            StorableFormScreen(
                vaultViewModel = vaultViewModel,
                defaultKind = kind,
                onSaved = { navController.popBackStack() },
                onBack = { navController.popBackStack() }
            )
        }

        composable(
            route = Routes.STORABLE_EDIT,
            arguments = listOf(navArgument("id") { type = NavType.StringType })
        ) { backStackEntry ->
            val id = backStackEntry.arguments?.getString("id") ?: return@composable
            val storable = vaultViewModel.uiState.value.storables.find { it.id == id }
            if (storable != null) {
                StorableFormScreen(
                    storable = storable,
                    vaultViewModel = vaultViewModel,
                    onSaved = { navController.popBackStack() },
                    onBack = { navController.popBackStack() }
                )
            }
        }
    }
}
