package com.seq.acheronmobile.ui.theme

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.res.painterResource
import com.seq.acheronmobile.R

/**
 * Fondo de marca compartido por las pantallas de autenticacion (login,
 * clave maestra): degradado radial oscuro con acento purpura, igual que
 * el fondo de las vistas de auth en web/app.
 */
@Composable
fun BrandAuthBackground(content: @Composable () -> Unit) {
    val colorScheme = MaterialTheme.colorScheme
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.radialGradient(
                    colors = listOf(
                        colorScheme.primary.copy(alpha = 0.10f),
                        colorScheme.background
                    ),
                    center = Offset(0.2f, 0.15f),
                    radius = 1400f
                )
            )
    ) {
        content()
    }
}

@Composable
fun AcheronLogo(modifier: Modifier = Modifier) {
    Image(
        painter = painterResource(id = R.drawable.acheron_logo),
        contentDescription = "Acheron",
        modifier = modifier
    )
}
