package com.seq.acheronmobile.data.repository

import com.seq.acheronmobile.data.model.BulkUpdateRequest
import com.seq.acheronmobile.data.model.BulkUpdateResponse
import com.seq.acheronmobile.data.model.StorableCreateRequest
import com.seq.acheronmobile.data.model.StorableDeleteRequest
import com.seq.acheronmobile.data.model.StorableResponse
import com.seq.acheronmobile.data.model.VaultUpsertResponse
import com.seq.acheronmobile.data.network.NetworkModule
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

class VaultRemoteDataSource(
    private val json: Json = Json { ignoreUnknownKeys = true }
) {
    private val api = NetworkModule.seqApiService

    sealed class Result<out T> {
        data class Success<T>(val data: T) : Result<T>()
        data class Error(val code: Int, val message: String) : Result<Nothing>()
        data object NetworkError : Result<Nothing>()
    }

    suspend fun fetchVault(): Result<JsonObject> {
        return try {
            val response = api.getVault()
            if (response.isSuccessful) {
                Result.Success(response.body()!!)
            } else {
                Result.Error(response.code(), errorMessage(response))
            }
        } catch (_: java.io.IOException) {
            Result.NetworkError
        } catch (e: Exception) {
            Result.Error(0, e.localizedMessage ?: "Unknown error")
        }
    }

    suspend fun pushVault(vault: JsonObject): Result<VaultUpsertResponse> {
        return try {
            val response = api.upsertVault(vault)
            if (response.isSuccessful) {
                Result.Success(response.body()!!)
            } else {
                Result.Error(response.code(), errorMessage(response))
            }
        } catch (_: java.io.IOException) {
            Result.NetworkError
        } catch (e: Exception) {
            Result.Error(0, e.localizedMessage ?: "Unknown error")
        }
    }

    suspend fun addStorable(request: StorableCreateRequest): Result<StorableResponse> {
        return try {
            val response = api.addStorable(request)
            if (response.isSuccessful) {
                Result.Success(response.body()!!)
            } else {
                Result.Error(response.code(), errorMessage(response))
            }
        } catch (_: java.io.IOException) {
            Result.NetworkError
        } catch (e: Exception) {
            Result.Error(0, e.localizedMessage ?: "Unknown error")
        }
    }

    suspend fun deleteStorable(internalId: String): Result<StorableResponse> {
        return try {
            val response = api.deleteStorable(StorableDeleteRequest(internalId))
            if (response.isSuccessful) {
                Result.Success(response.body()!!)
            } else {
                Result.Error(response.code(), errorMessage(response))
            }
        } catch (_: java.io.IOException) {
            Result.NetworkError
        } catch (e: Exception) {
            Result.Error(0, e.localizedMessage ?: "Unknown error")
        }
    }

    suspend fun bulkUpdate(requests: List<BulkUpdateRequest>): Result<BulkUpdateResponse> {
        return try {
            val response = api.bulkUpdateStorables(requests)
            if (response.isSuccessful) {
                Result.Success(response.body()!!)
            } else {
                Result.Error(response.code(), errorMessage(response))
            }
        } catch (_: java.io.IOException) {
            Result.NetworkError
        } catch (e: Exception) {
            Result.Error(0, e.localizedMessage ?: "Unknown error")
        }
    }

    private fun errorMessage(response: retrofit2.Response<*>): String {
        val fallback = when (response.code()) {
            401 -> "Sesion expirada"
            403 -> "No tienes permisos para realizar esta accion"
            404 -> "No encontrado"
            409 -> "Ya existe"
            429 -> "Demasiadas peticiones"
            else -> "Error ${response.code()}"
        }
        return try {
            val body = response.errorBody()?.string() ?: ""
            json.decodeFromString<com.seq.acheronmobile.data.model.ApiErrorResponse>(body)
                .displayMessage() ?: fallback
        } catch (_: Exception) {
            fallback
        }
    }
}
