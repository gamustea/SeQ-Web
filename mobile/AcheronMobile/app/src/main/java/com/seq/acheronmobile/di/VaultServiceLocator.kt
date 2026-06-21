package com.seq.acheronmobile.di

import com.seq.acheronmobile.data.repository.VaultRemoteDataSource
import com.seq.acheronmobile.data.vault.VaultCryptoService

object VaultServiceLocator {
    lateinit var cryptoService: VaultCryptoService
    lateinit var remoteDataSource: VaultRemoteDataSource
    var username: String = ""
}