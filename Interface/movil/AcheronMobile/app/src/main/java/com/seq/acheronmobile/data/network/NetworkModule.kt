package com.seq.acheronmobile.data.network

import com.jakewharton.retrofit2.converter.kotlinx.serialization.asConverterFactory
import com.seq.acheronmobile.BuildConfig
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import java.util.concurrent.TimeUnit

/**
 * Singleton que provee la instancia de Retrofit.
 * En un proyecto con Hilt esto sería un @Module; aquí usamos object
 * para mantener el ejemplo sin DI framework.
 */
object NetworkModule {

    private val json = Json {
        ignoreUnknownKeys = true   // la API puede añadir campos sin romper el cliente
        isLenient = true
        encodeDefaults = true
    }

    private val okHttpClient: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .addInterceptor { chain ->
                val request = chain.request().newBuilder()
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build()
                chain.proceed(request)
            }
            .apply {
                if (BuildConfig.DEBUG) {
                    addInterceptor(
                        HttpLoggingInterceptor().apply {
                            level = HttpLoggingInterceptor.Level.BODY
                        }
                    )
                }
            }
            .build()
    }

    val seqApiService: SeqApiService by lazy {
        Retrofit.Builder()
            .baseUrl(BuildConfig.SEQ_BASE_URL)
            .client(okHttpClient)
            .addConverterFactory(
                json.asConverterFactory("application/json".toMediaType())
            )
            .build()
            .create(SeqApiService::class.java)
    }
}