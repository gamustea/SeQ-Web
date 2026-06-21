package com.seq.acheronmobile.ui.theme

import android.provider.Settings
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.seq.acheronmobile.R
import kotlin.math.cos
import kotlin.math.sin

/*
 * Sistema de diseño Acheron.
 *
 * Acheron es el rio del inframundo griego; este es el guardian de tus secretos
 * en su travesia. La identidad es clasica y heraldica: rio purpura (amatista)
 * como hilo conductor, oro laurel como acento ceremonial y muy contenido, sobre
 * el abismo casi negro. Estos componentes sustituyen al "chrome" por defecto de
 * Material para que la app no se lea como una app basica de Compose.
 */

// ── Tokens de marca ─────────────────────────────────────────────────────────

val AcheronGold = Color(0xFFE8BC6A)
val AcheronAbyss = Color(0xFF0B0C10)
val AcheronAbyssDeep = Color(0xFF07080B)
private val RiverLight = Color(0xFFD7C2F2)
private val RiverDeep = Color(0xFF7B5AA6)
private val Hairline = Color(0xFF272938)

object BrandSpace {
    val xs = 4.dp
    val sm = 8.dp
    val md = 16.dp
    val lg = 24.dp
    val xl = 36.dp
}

private val PanelShape = RoundedCornerShape(20.dp)
private val ControlShape = RoundedCornerShape(14.dp)

/** Detecta si el usuario ha desactivado las animaciones del sistema. */
@Composable
fun rememberReducedMotion(): Boolean {
    val context = LocalContext.current
    return remember {
        val scale = Settings.Global.getFloat(
            context.contentResolver,
            Settings.Global.ANIMATOR_DURATION_SCALE,
            1f
        )
        scale == 0f
    }
}

// ── Fondo ambiental: la corriente del rio ───────────────────────────────────

/**
 * Fondo de marca para las pantallas de autenticacion: el abismo con corrientes
 * de amatista a la deriva. Se anima muy lentamente (la "corriente" del Acheron)
 * y respeta la preferencia de movimiento reducido del sistema.
 */
@Composable
fun AcheronAmbientBackground(
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit
) {
    val reduced = rememberReducedMotion()
    val transition = rememberInfiniteTransition(label = "current")
    val phase by transition.animateFloat(
        initialValue = 0f,
        targetValue = (2f * Math.PI).toFloat(),
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 24000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "phase"
    )
    val p = if (reduced) 1.2f else phase
    val primary = MaterialTheme.colorScheme.primary

    Box(modifier = modifier.fillMaxSize().background(AcheronAbyss)) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            val w = size.width
            val h = size.height

            // Base: descenso al abismo
            drawRect(
                brush = Brush.verticalGradient(
                    0f to AcheronAbyssDeep,
                    0.5f to AcheronAbyss,
                    1f to AcheronAbyssDeep
                )
            )

            // Corriente superior (amatista) a la deriva
            val c1 = Offset(w * (0.22f + 0.06f * cos(p)), h * (0.16f + 0.03f * sin(p)))
            drawRect(
                brush = Brush.radialGradient(
                    colors = listOf(primary.copy(alpha = 0.16f), Color.Transparent),
                    center = c1,
                    radius = w * 0.95f
                )
            )

            // Remanso inferior (oro muy tenue) — el destello ceremonial
            val c2 = Offset(w * (0.82f - 0.05f * sin(p * 0.8f)), h * (0.86f + 0.03f * cos(p * 0.8f)))
            drawRect(
                brush = Brush.radialGradient(
                    colors = listOf(AcheronGold.copy(alpha = 0.06f), Color.Transparent),
                    center = c2,
                    radius = w * 0.8f
                )
            )

            // Vineta para sujetar el contenido al centro
            drawRect(
                brush = Brush.radialGradient(
                    colors = listOf(Color.Transparent, AcheronAbyssDeep.copy(alpha = 0.6f)),
                    center = Offset(w / 2f, h / 2f),
                    radius = w * 1.1f
                )
            )
        }
        content()
    }
}

// ── Logotipo / lockup ───────────────────────────────────────────────────────

/** Marca del rio Acheron (amatista sobre transparente). */
@Composable
fun AcheronMark(modifier: Modifier = Modifier) {
    Image(
        painter = painterResource(id = R.drawable.acheron_river),
        contentDescription = "Acheron",
        modifier = modifier
    )
}

/**
 * Lockup vertical de marca: regla + epigrafe, la marca del rio y el wordmark
 * "ACHERON" en Syne con tracking amplio, con un subtitulo opcional.
 */
@Composable
fun AcheronLockup(
    modifier: Modifier = Modifier,
    eyebrow: String = "SeQ · BÓVEDA DE SECRETOS",
    subtitle: String? = null,
    markSize: Dp = 96.dp
) {
    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(BrandSpace.sm)
    ) {
        AcheronMark(modifier = Modifier.size(markSize))
        Spacer(Modifier.height(BrandSpace.xs))
        BrandEyebrow(eyebrow)
        Text(
            text = "ACHERON",
            style = MaterialTheme.typography.displaySmall,
            color = MaterialTheme.colorScheme.onBackground,
            letterSpacing = 8.sp
        )
        if (subtitle != null) {
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )
        }
    }
}

/** Epigrafe: regla corta dorada + texto en versales con tracking. */
@Composable
fun BrandEyebrow(text: String, modifier: Modifier = Modifier) {
    Row(
        modifier = modifier,
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(BrandSpace.sm)
    ) {
        Box(
            Modifier
                .width(18.dp)
                .height(1.dp)
                .background(AcheronGold.copy(alpha = 0.7f))
        )
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            color = AcheronGold,
            letterSpacing = 3.sp,
            fontWeight = FontWeight.Medium
        )
        Box(
            Modifier
                .width(18.dp)
                .height(1.dp)
                .background(AcheronGold.copy(alpha = 0.7f))
        )
    }
}

/** Etiqueta de seccion: versales pequeñas y silenciadas. */
@Composable
fun SectionLabel(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text.uppercase(),
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        letterSpacing = 2.sp,
        fontWeight = FontWeight.SemiBold,
        modifier = modifier
    )
}

// ── Superficies ─────────────────────────────────────────────────────────────

/**
 * Panel de marca: superficie elevada de obsidiana con borde de hilo y una
 * fina linea de acento (rio) en la parte superior. La unidad de composicion
 * de toda la app.
 */
@Composable
fun BrandPanel(
    modifier: Modifier = Modifier,
    accent: Boolean = true,
    content: @Composable () -> Unit
) {
    Column(
        modifier = modifier
            .clip(PanelShape)
            .background(MaterialTheme.colorScheme.surfaceContainer)
            .border(1.dp, Hairline, PanelShape)
    ) {
        if (accent) {
            Box(
                Modifier
                    .fillMaxWidth()
                    .height(2.dp)
                    .background(
                        Brush.horizontalGradient(
                            listOf(Color.Transparent, RiverLight, AcheronGold, Color.Transparent)
                        )
                    )
            )
        }
        Column(content = { content() })
    }
}

// ── Controles ───────────────────────────────────────────────────────────────

/** Boton primario de marca: degradado de rio, foco y ripple accesibles. */
@Composable
fun BrandPrimaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    loading: Boolean = false
) {
    val active = enabled && !loading
    val interaction = remember { MutableInteractionSource() }
    Box(
        modifier = modifier
            .height(54.dp)
            .clip(ControlShape)
            .background(
                if (active)
                    Brush.horizontalGradient(listOf(RiverDeep, MaterialTheme.colorScheme.primary))
                else
                    Brush.horizontalGradient(
                        listOf(
                            MaterialTheme.colorScheme.surfaceContainerHighest,
                            MaterialTheme.colorScheme.surfaceContainerHighest
                        )
                    )
            )
            .clickable(
                enabled = active,
                interactionSource = interaction,
                indication = androidx.compose.material3.ripple()
            ) { onClick() },
        contentAlignment = Alignment.Center
    ) {
        if (loading) {
            CircularProgressIndicator(
                modifier = Modifier.size(22.dp),
                strokeWidth = 2.dp,
                color = MaterialTheme.colorScheme.onPrimary
            )
        } else {
            Text(
                text = text,
                style = MaterialTheme.typography.titleSmall,
                color = if (active) MaterialTheme.colorScheme.onPrimary
                else MaterialTheme.colorScheme.onSurfaceVariant,
                letterSpacing = 0.5.sp
            )
        }
    }
}

/** Boton secundario: contorno de hilo, sin relleno. */
@Composable
fun BrandSecondaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    loading: Boolean = false,
    leadingIcon: ImageVector? = null,
    accent: Color? = null
) {
    val active = enabled && !loading
    val tint = accent ?: MaterialTheme.colorScheme.onSurface
    val interaction = remember { MutableInteractionSource() }
    Box(
        modifier = modifier
            .height(52.dp)
            .clip(ControlShape)
            .border(1.dp, if (active) Hairline else Hairline.copy(alpha = 0.5f), ControlShape)
            .clickable(
                enabled = active,
                interactionSource = interaction,
                indication = androidx.compose.material3.ripple()
            ) { onClick() },
        contentAlignment = Alignment.Center
    ) {
        if (loading) {
            CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
        } else {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(BrandSpace.sm)) {
                if (leadingIcon != null) {
                    Icon(leadingIcon, contentDescription = null, tint = tint, modifier = Modifier.size(18.dp))
                }
                Text(
                    text = text,
                    style = MaterialTheme.typography.titleSmall,
                    color = if (active) tint else tint.copy(alpha = 0.5f),
                    letterSpacing = 0.5.sp
                )
            }
        }
    }
}

// ── Avisos ──────────────────────────────────────────────────────────────────

/**
 * Aviso ceremonial dorado: para advertencias de seguridad de alto peso (p. ej.
 * "esta clave es esencial y no se puede recuperar").
 */
@Composable
fun WarningCallout(
    icon: ImageVector,
    title: String,
    body: String,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier
            .clip(ControlShape)
            .background(AcheronGold.copy(alpha = 0.08f))
            .border(1.dp, AcheronGold.copy(alpha = 0.35f), ControlShape)
            .padding(BrandSpace.md),
        horizontalArrangement = Arrangement.spacedBy(BrandSpace.md)
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = AcheronGold,
            modifier = Modifier.size(22.dp)
        )
        Column(verticalArrangement = Arrangement.spacedBy(BrandSpace.xs)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                color = AcheronGold
            )
            Text(
                text = body,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                lineHeight = 18.sp
            )
        }
    }
}

// ── Medidor de fortaleza de clave ────────────────────────────────────────────

data class Strength(val score: Int, val label: String, val color: Color)

@Composable
fun rememberStrength(password: String): Strength {
    val errorColor = MaterialTheme.colorScheme.error
    val primary = MaterialTheme.colorScheme.primary
    return remember(password) {
        if (password.isEmpty()) return@remember Strength(0, "", Color.Transparent)
        var score = 0
        if (password.length >= 8) score++
        if (password.length >= 12) score++
        if (password.any { it.isDigit() } && password.any { it.isLetter() }) score++
        if (password.any { !it.isLetterOrDigit() }) score++
        when (score) {
            0, 1 -> Strength(1, "Débil", errorColor)
            2 -> Strength(2, "Aceptable", Color(0xFFE0A53C))
            3 -> Strength(3, "Buena", AcheronGold)
            else -> Strength(4, "Fuerte", primary)
        }
    }
}

/** Barra segmentada de fortaleza de clave. */
@Composable
fun PasswordStrengthMeter(password: String, modifier: Modifier = Modifier) {
    val s = rememberStrength(password)
    if (password.isEmpty()) return
    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(BrandSpace.xs)) {
        Row(horizontalArrangement = Arrangement.spacedBy(BrandSpace.xs)) {
            repeat(4) { i ->
                Box(
                    Modifier
                        .weight(1f)
                        .height(4.dp)
                        .clip(CircleShape)
                        .background(
                            if (i < s.score) s.color
                            else MaterialTheme.colorScheme.surfaceContainerHighest
                        )
                )
            }
        }
        Text(
            text = "Fortaleza: ${s.label}",
            style = MaterialTheme.typography.labelSmall,
            color = s.color
        )
    }
}

/** Tipografia monoespaciada para valores sensibles. */
@Composable
fun secretTextStyle(): TextStyle =
    MaterialTheme.typography.bodyLarge.copy(
        fontFamily = monoFontFamily,
        letterSpacing = 1.sp
    )
