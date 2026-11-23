package com.shieldforge.app.core.storage

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "projects")
data class ProjectEntity(
    @PrimaryKey val projectId: String,
    val name: String,
    val packageName: String,
    val versionName: String,
    val mode: String,
    val fileSizeBytes: Long,
    val dexCount: Int,
    val classCount: Int,
    val lastProfileName: String,
    val lastStatus: String,
    val updatedAtMs: Long,
    val analysisCachePath: String,
)

@Entity(tableName = "build_history")
data class BuildHistoryEntity(
    @PrimaryKey val reportId: String,
    val projectId: String,
    val projectName: String,
    val packageName: String,
    val mode: String,
    val profileName: String,
    val succeeded: Boolean,
    val outputPath: String,
    val reportJsonPath: String,
    val buildDurationMs: Long,
    val createdAtMs: Long,
    val summary: String,
)

@Entity(tableName = "custom_profiles")
data class CustomProfileEntity(
    @PrimaryKey val profileId: String,
    val name: String,
    val description: String,
    val profileJson: String,
    val updatedAtMs: Long,
)

@Entity(tableName = "signing_profiles")
data class SigningProfileEntity(
    @PrimaryKey val id: String,
    val alias: String,
    val storageKind: String,
    val keystoreFileName: String?,
    val commonName: String,
    val organization: String,
    val sha256Fingerprint: String,
    val sha1Fingerprint: String,
    val createdAtMs: Long,
)

@Dao
interface ProjectDao {
    @Query("SELECT * FROM projects ORDER BY updatedAtMs DESC")
    fun observeAll(): Flow<List<ProjectEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(item: ProjectEntity)

    @Query("DELETE FROM projects WHERE projectId = :id")
    suspend fun deleteById(id: String)
}

@Dao
interface BuildHistoryDao {
    @Query("SELECT * FROM build_history ORDER BY createdAtMs DESC")
    fun observeAll(): Flow<List<BuildHistoryEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(item: BuildHistoryEntity)
}

@Dao
interface ProfileDao {
    @Query("SELECT * FROM custom_profiles ORDER BY updatedAtMs DESC")
    fun observeAll(): Flow<List<CustomProfileEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(item: CustomProfileEntity)

    @Query("DELETE FROM custom_profiles WHERE profileId = :id")
    suspend fun deleteById(id: String)
}

@Dao
interface SigningDao {
    @Query("SELECT * FROM signing_profiles ORDER BY createdAtMs DESC")
    fun observeAll(): Flow<List<SigningProfileEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(item: SigningProfileEntity)

    @Query("DELETE FROM signing_profiles WHERE id = :id")
    suspend fun deleteById(id: String)
}

@Database(
    entities = [
        ProjectEntity::class,
        BuildHistoryEntity::class,
        CustomProfileEntity::class,
        SigningProfileEntity::class,
    ],
    version = 1,
    exportSchema = false,
)
abstract class ForgeDatabase : RoomDatabase() {
    abstract fun projectDao(): ProjectDao
    abstract fun buildHistoryDao(): BuildHistoryDao
    abstract fun profileDao(): ProfileDao
    abstract fun signingDao(): SigningDao

    companion object {
        @Volatile
        private var INSTANCE: ForgeDatabase? = null

        fun getInstance(context: Context): ForgeDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    ForgeDatabase::class.java,
                    "shieldforge_studio.db",
                ).build().also { INSTANCE = it }
            }
        }
    }
}
