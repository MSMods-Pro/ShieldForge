package com.shieldforge.app.apk.dex

import com.shieldforge.app.core.common.CompatibilityState
import com.shieldforge.app.core.common.ComponentStatus
import com.shieldforge.app.core.crypto.CryptoEngine
import java.nio.ByteBuffer
import java.nio.ByteOrder

object DexBinaryParser {
    private const val DEX_ENDIAN_CONSTANT = 0x12345678
    private const val NO_INDEX = -1
    private val SUPPORTED_VERSIONS = setOf("035", "037", "038", "039", "040", "041")

    private const val ACC_PUBLIC = 0x0001
    private const val ACC_PRIVATE = 0x0002
    private const val ACC_PROTECTED = 0x0004
    private const val ACC_STATIC = 0x0008
    private const val ACC_FINAL = 0x0010
    private const val ACC_SYNCHRONIZED = 0x0020
    private const val ACC_BRIDGE = 0x0040
    private const val ACC_NATIVE = 0x0100
    private const val ACC_INTERFACE = 0x0200
    private const val ACC_ABSTRACT = 0x0400
    private const val ACC_SYNTHETIC = 0x1000
    private const val ACC_ANNOTATION = 0x2000
    private const val ACC_ENUM = 0x4000

    data class ParsedSingleDex(
        val summary: DexFileSummary,
        val classes: List<DexClassItem>,
        val methods: List<DexMethodItem>,
        val fields: List<DexFieldItem>,
        val strings: List<DexStringItem>,
    )

    fun parseSingleDex(
        fileName: String,
        bytes: ByteArray,
        manifestComponentClasses: Set<String> = emptySet(),
    ): ParsedSingleDex {
        val sha256 = CryptoEngine.sha256Hex(bytes)
        if (bytes.size < 112) {
            return emptyErrorDex(fileName, bytes.size, sha256, "Truncated DEX header (<112 bytes)")
        }
        val magicBytes = bytes.copyOfRange(0, 8)
        val magicStr = String(magicBytes, Charsets.US_ASCII)
        if (!magicStr.startsWith("dex\n") || magicBytes[7].toInt() != 0) {
            return emptyErrorDex(fileName, bytes.size, sha256, "Invalid DEX magic header")
        }
        val version = magicStr.substring(4, 7)
        val isSupportedVersion = version in SUPPORTED_VERSIONS

        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val storedAdler = buf.getInt(8).toLong() and 0xFFFFFFFFL
        val computedAdler = CryptoEngine.adler32(bytes, 12, bytes.size - 12)
        val adlerValid = storedAdler == computedAdler

        val storedSha1 = bytes.copyOfRange(12, 32)
        val computedSha1 = CryptoEngine.sha1Bytes(bytes.copyOfRange(32, bytes.size))
        val sha1Valid = storedSha1.contentEquals(computedSha1)

        val fileSize = buf.getInt(32)
        val headerSize = buf.getInt(36)
        val endianTag = buf.getInt(40)
        if (endianTag != DEX_ENDIAN_CONSTANT || headerSize < 0x70 || fileSize > bytes.size) {
            return emptyErrorDex(
                fileName,
                bytes.size,
                sha256,
                "Malformed DEX structure (endian/header/size mismatch)",
                version,
                adlerValid,
                sha1Valid,
            )
        }

        val stringIdsSize = buf.getInt(56)
        val stringIdsOff = buf.getInt(60)
        val typeIdsSize = buf.getInt(64)
        val typeIdsOff = buf.getInt(68)
        val protoIdsSize = buf.getInt(72)
        val protoIdsOff = buf.getInt(76)
        val fieldIdsSize = buf.getInt(80)
        val fieldIdsOff = buf.getInt(84)
        val methodIdsSize = buf.getInt(88)
        val methodIdsOff = buf.getInt(92)
        val classDefsSize = buf.getInt(96)
        val classDefsOff = buf.getInt(100)

        return try {
            val rawStrings = ArrayList<String>(stringIdsSize.coerceAtMost(200_000))
            for (i in 0 until stringIdsSize) {
                val idPos = stringIdsOff + i * 4
                if (idPos + 4 > bytes.size) break
                val strDataOff = buf.getInt(idPos)
                rawStrings.add(readMutf8String(bytes, strDataOff))
            }

            val typeDescriptors = ArrayList<String>(typeIdsSize.coerceAtMost(100_000))
            for (i in 0 until typeIdsSize) {
                val pos = typeIdsOff + i * 4
                if (pos + 4 > bytes.size) break
                val strIdx = buf.getInt(pos)
                typeDescriptors.add(rawStrings.getOrElse(strIdx) { "Lunknown;" })
            }

            val protoSignatures = ArrayList<Pair<String, List<String>>>(protoIdsSize.coerceAtMost(100_000))
            for (i in 0 until protoIdsSize) {
                val pos = protoIdsOff + i * 12
                if (pos + 12 > bytes.size) break
                val returnTypeIdx = buf.getInt(pos + 4)
                val paramsOff = buf.getInt(pos + 8)
                val retType = descriptorToJavaName(typeDescriptors.getOrElse(returnTypeIdx) { "V" })
                val params = if (paramsOff > 0 && paramsOff + 4 <= bytes.size) {
                    val count = buf.getInt(paramsOff)
                    (0 until count.coerceAtMost(64)).mapNotNull { p ->
                        val itemPos = paramsOff + 4 + p * 2
                        if (itemPos + 2 <= bytes.size) {
                            val tIdx = buf.getShort(itemPos).toInt() and 0xFFFF
                            descriptorToJavaName(typeDescriptors.getOrElse(tIdx) { "?" })
                        } else null
                    }
                } else emptyList()
                protoSignatures.add(retType to params)
            }

            // Read Field IDs
            val fieldIdRecords = ArrayList<Triple<String, String, String>>(fieldIdsSize.coerceAtMost(150_000))
            for (i in 0 until fieldIdsSize) {
                val pos = fieldIdsOff + i * 8
                if (pos + 8 > bytes.size) break
                val classIdx = buf.getShort(pos).toInt() and 0xFFFF
                val typeIdx = buf.getShort(pos + 2).toInt() and 0xFFFF
                val nameIdx = buf.getInt(pos + 4)
                fieldIdRecords.add(
                    Triple(
                        descriptorToJavaName(typeDescriptors.getOrElse(classIdx) { "Lunknown;" }),
                        descriptorToJavaName(typeDescriptors.getOrElse(typeIdx) { "Ljava/lang/Object;" }),
                        rawStrings.getOrElse(nameIdx) { "field_$i" },
                    ),
                )
            }

            // Read Method IDs
            data class MethodIdRec(
                val declaringClass: String,
                val returnType: String,
                val params: List<String>,
                val name: String,
            )
            val methodIdRecords = ArrayList<MethodIdRec>(methodIdsSize.coerceAtMost(200_000))
            for (i in 0 until methodIdsSize) {
                val pos = methodIdsOff + i * 8
                if (pos + 8 > bytes.size) break
                val classIdx = buf.getShort(pos).toInt() and 0xFFFF
                val protoIdx = buf.getShort(pos + 2).toInt() and 0xFFFF
                val nameIdx = buf.getInt(pos + 4)
                val proto = protoSignatures.getOrElse(protoIdx) { "void" to emptyList() }
                methodIdRecords.add(
                    MethodIdRec(
                        declaringClass = descriptorToJavaName(typeDescriptors.getOrElse(classIdx) { "Lunknown;" }),
                        returnType = proto.first,
                        params = proto.second,
                        name = rawStrings.getOrElse(nameIdx) { "method_$i" },
                    ),
                )
            }

            // Detect global reflection / JNI usage indicators in method IDs
            val hasGlobalReflection = methodIdRecords.any {
                it.declaringClass == "java.lang.Class" &&
                    (it.name == "forName" || it.name.startsWith("getDeclared"))
            }
            val sourceFileStringIndices = HashSet<Int>()

            val parsedClasses = ArrayList<DexClassItem>(classDefsSize)
            val parsedMethods = ArrayList<DexMethodItem>()
            val parsedFields = ArrayList<DexFieldItem>()
            val seenMethodIndices = HashSet<Int>()
            val seenFieldIndices = HashSet<Int>()
            val packageSet = HashSet<String>()

            for (i in 0 until classDefsSize) {
                val pos = classDefsOff + i * 32
                if (pos + 32 > bytes.size) break
                val classIdx = buf.getInt(pos)
                val accessFlags = buf.getInt(pos + 4)
                val superIdx = buf.getInt(pos + 8)
                val interfacesOff = buf.getInt(pos + 12)
                val sourceFileIdx = buf.getInt(pos + 16)
                val classDataOff = buf.getInt(pos + 24)

                if (sourceFileIdx >= 0 && sourceFileIdx < rawStrings.size) {
                    sourceFileStringIndices.add(sourceFileIdx)
                }

                val descriptor = typeDescriptors.getOrElse(classIdx) { "Lunknown/Class$i;" }
                val fqcn = descriptorToJavaName(descriptor)
                val lastDot = fqcn.lastIndexOf('.')
                val pkgName = if (lastDot > 0) fqcn.substring(0, lastDot) else "(default)"
                val simpleName = if (lastDot > 0) fqcn.substring(lastDot + 1) else fqcn
                packageSet.add(pkgName)

                val superClass = if (superIdx != NO_INDEX) {
                    descriptorToJavaName(typeDescriptors.getOrElse(superIdx) { "Ljava/lang/Object;" })
                } else "java.lang.Object"

                val interfaces = if (interfacesOff > 0 && interfacesOff + 4 <= bytes.size) {
                    val count = buf.getInt(interfacesOff)
                    (0 until count.coerceAtMost(32)).mapNotNull { idx ->
                        val itemPos = interfacesOff + 4 + idx * 2
                        if (itemPos + 2 <= bytes.size) {
                            val tIdx = buf.getShort(itemPos).toInt() and 0xFFFF
                            descriptorToJavaName(typeDescriptors.getOrElse(tIdx) { "?" })
                        } else null
                    }
                } else emptyList()

                val sourceFile = if (sourceFileIdx != NO_INDEX) rawStrings.getOrNull(sourceFileIdx) else null

                var classMethodCount = 0
                var classFieldCount = 0
                var hasNativeMethod = false

                if (classDataOff > 0 && classDataOff < bytes.size) {
                    val cursor = intArrayOf(classDataOff)
                    val staticFieldsSize = readUleb128(bytes, cursor)
                    val instanceFieldsSize = readUleb128(bytes, cursor)
                    val directMethodsSize = readUleb128(bytes, cursor)
                    val virtualMethodsSize = readUleb128(bytes, cursor)

                    fun parseEncodedFields(count: Int, isStatic: Boolean) {
                        var fieldIdx = 0
                        for (f in 0 until count.coerceAtMost(4096)) {
                            fieldIdx += readUleb128(bytes, cursor)
                            val fFlags = readUleb128(bytes, cursor)
                            classFieldCount++
                            if (seenFieldIndices.add(fieldIdx)) {
                                val rec = fieldIdRecords.getOrNull(fieldIdx)
                                if (rec != null) {
                                    val isSynthetic = (fFlags and ACC_SYNTHETIC) != 0
                                    val isManifestOwner = fqcn in manifestComponentClasses
                                    val compat = when {
                                        isManifestOwner -> CompatibilityState.CAUTION_FRAMEWORK_ENTRY
                                        else -> CompatibilityState.REQUIRES_SOURCE_R8
                                    }
                                    parsedFields.add(
                                        DexFieldItem(
                                            id = "$fileName#F#$fieldIdx",
                                            dexFileName = fileName,
                                            fieldIdx = fieldIdx,
                                            declaringClass = rec.first,
                                            name = rec.third,
                                            fieldType = rec.second,
                                            accessFlags = fFlags,
                                            modifiers = decodeModifiers(fFlags, isMethod = false),
                                            isStatic = isStatic,
                                            isSynthetic = isSynthetic,
                                            compatibility = compat,
                                            status = ComponentStatus.SELECTABLE,
                                        ),
                                    )
                                }
                            }
                        }
                    }

                    fun parseEncodedMethods(count: Int, isDirect: Boolean) {
                        var methodIdx = 0
                        for (m in 0 until count.coerceAtMost(4096)) {
                            methodIdx += readUleb128(bytes, cursor)
                            val mFlags = readUleb128(bytes, cursor)
                            readUleb128(bytes, cursor) // code_off
                            classMethodCount++
                            val isNative = (mFlags and ACC_NATIVE) != 0
                            if (isNative) hasNativeMethod = true
                            if (seenMethodIndices.add(methodIdx)) {
                                val rec = methodIdRecords.getOrNull(methodIdx)
                                if (rec != null) {
                                    val isSynthetic = (mFlags and ACC_SYNTHETIC) != 0
                                    val compat = when {
                                        isNative -> CompatibilityState.CAUTION_JNI
                                        fqcn in manifestComponentClasses -> CompatibilityState.CAUTION_FRAMEWORK_ENTRY
                                        hasGlobalReflection && rec.name.contains("invoke") ->
                                            CompatibilityState.CAUTION_REFLECTION
                                        else -> CompatibilityState.REQUIRES_SOURCE_R8
                                    }
                                    parsedMethods.add(
                                        DexMethodItem(
                                            id = "$fileName#M#$methodIdx",
                                            dexFileName = fileName,
                                            methodIdx = methodIdx,
                                            declaringClass = rec.declaringClass,
                                            name = rec.name,
                                            returnType = rec.returnType,
                                            parameterTypes = rec.params,
                                            signature = "${rec.name}(${rec.params.joinToString(",")}):${rec.returnType}",
                                            accessFlags = mFlags,
                                            modifiers = decodeModifiers(mFlags, isMethod = true),
                                            isDirect = isDirect,
                                            isNative = isNative,
                                            isSynthetic = isSynthetic,
                                            compatibility = compat,
                                            status = ComponentStatus.SELECTABLE,
                                        ),
                                    )
                                }
                            }
                        }
                    }

                    parseEncodedFields(staticFieldsSize, isStatic = true)
                    parseEncodedFields(instanceFieldsSize, isStatic = false)
                    parseEncodedMethods(directMethodsSize, isDirect = true)
                    parseEncodedMethods(virtualMethodsSize, isDirect = false)
                }

                val isManifestOwner = fqcn in manifestComponentClasses
                val classCompat = when {
                    !isSupportedVersion -> CompatibilityState.INCOMPATIBLE
                    hasNativeMethod -> CompatibilityState.CAUTION_JNI
                    isManifestOwner -> CompatibilityState.CAUTION_FRAMEWORK_ENTRY
                    hasGlobalReflection && (fqcn.contains("Reflect") || fqcn.contains("Gson") || fqcn.contains("Json")) ->
                        CompatibilityState.CAUTION_REFLECTION
                    else -> CompatibilityState.COMPATIBLE
                }
                val classStatus = if (sourceFileIdx != NO_INDEX && isSupportedVersion) {
                    ComponentStatus.TRANSFORMABLE
                } else {
                    ComponentStatus.SELECTABLE
                }

                parsedClasses.add(
                    DexClassItem(
                        id = "$fileName#C#$i",
                        dexFileName = fileName,
                        classDefIndex = i,
                        descriptor = descriptor,
                        className = fqcn,
                        simpleName = simpleName,
                        packageName = pkgName,
                        superClass = superClass,
                        interfaces = interfaces,
                        sourceFile = sourceFile,
                        sourceFileIdx = sourceFileIdx,
                        accessFlags = accessFlags,
                        modifiers = decodeModifiers(accessFlags, isMethod = false),
                        methodCount = classMethodCount,
                        fieldCount = classFieldCount,
                        hasReflectionIndicators = hasGlobalReflection &&
                            (fqcn.contains("Reflect") || fqcn.contains("Factory") || fqcn.contains("Adapter")),
                        hasJniIndicators = hasNativeMethod,
                        isManifestComponent = isManifestOwner,
                        compatibility = classCompat,
                        status = classStatus,
                    ),
                )
            }

            // Build string inventory (bounded reasonably if massive, prioritizing sensitive + source tags + user strings)
            val parsedStrings = rawStrings.mapIndexedNotNull { idx, value ->
                if (value.isEmpty() || value.length > 512) return@mapIndexedNotNull null
                val isSourceTag = idx in sourceFileStringIndices
                val sensitivity = classifyString(value)
                // Keep all sensitive/source strings and up to first 2,500 general strings to maintain crisp UI performance
                if (idx >= 2500 && sensitivity == StringSensitivity.NORMAL && !isSourceTag) {
                    return@mapIndexedNotNull null
                }
                DexStringItem(
                    id = "$fileName#S#$idx",
                    dexFileName = fileName,
                    index = idx,
                    value = value,
                    sensitivity = sensitivity,
                    isSourceFileTag = isSourceTag,
                    status = if (isSourceTag || sensitivity != StringSensitivity.NORMAL) {
                        ComponentStatus.TRANSFORMABLE
                    } else {
                        ComponentStatus.SELECTABLE
                    },
                )
            }

            val summary = DexFileSummary(
                fileName = fileName,
                version = version,
                isSupportedVersion = isSupportedVersion,
                fileSizeBytes = bytes.size,
                adler32Valid = adlerValid,
                sha1Valid = sha1Valid,
                sha256Hex = sha256,
                stringCount = stringIdsSize,
                typeCount = typeIdsSize,
                protoCount = protoIdsSize,
                fieldCount = fieldIdsSize,
                methodCount = methodIdsSize,
                classCount = classDefsSize,
                packageCount = packageSet.size,
                compatibility = if (isSupportedVersion) CompatibilityState.COMPATIBLE else CompatibilityState.INCOMPATIBLE,
                status = if (isSupportedVersion && adlerValid && sha1Valid) {
                    ComponentStatus.TRANSFORMABLE
                } else {
                    ComponentStatus.INSPECTABLE
                },
            )
            ParsedSingleDex(summary, parsedClasses, parsedMethods, parsedFields, parsedStrings)
        } catch (e: Exception) {
            emptyErrorDex(
                fileName,
                bytes.size,
                sha256,
                "DEX parse error: ${e.message ?: "unknown"}",
                version,
                adlerValid,
                sha1Valid,
            )
        }
    }

    fun analyzeAllDex(
        dexEntries: Map<String, ByteArray>,
        manifestComponentClasses: Set<String> = emptySet(),
    ): DexAnalysisBundle {
        val sortedNames = dexEntries.keys.sortedWith(compareBy({ dexOrder(it) }, { it }))
        val summaries = mutableListOf<DexFileSummary>()
        val allClasses = mutableListOf<DexClassItem>()
        val allMethods = mutableListOf<DexMethodItem>()
        val allFields = mutableListOf<DexFieldItem>()
        val allStrings = mutableListOf<DexStringItem>()

        for (name in sortedNames) {
            val parsed = parseSingleDex(name, dexEntries[name] ?: continue, manifestComponentClasses)
            summaries.add(parsed.summary)
            allClasses.addAll(parsed.classes)
            allMethods.addAll(parsed.methods)
            allFields.addAll(parsed.fields)
            allStrings.addAll(parsed.strings)
        }

        // Group into hierarchical Package nodes
        val packageNodes = allClasses.groupBy { it.packageName }.map { (pkg, clsList) ->
            DexPackageNode(
                packageName = pkg,
                dexFiles = clsList.map { it.dexFileName }.distinct(),
                classCount = clsList.size,
                methodCount = clsList.sumOf { it.methodCount },
                fieldCount = clsList.sumOf { it.fieldCount },
                stringCount = allStrings.count { it.value.contains(pkg) },
                hasCautionComponents = clsList.any { it.compatibility != CompatibilityState.COMPATIBLE },
            )
        }.sortedBy { it.packageName }

        val crossDexRefs = if (summaries.size > 1) {
            val classToDex = allClasses.associate { it.className to it.dexFileName }
            allClasses.mapNotNull { cls ->
                val superDex = classToDex[cls.superClass]
                if (superDex != null && superDex != cls.dexFileName) {
                    "${cls.className} (${cls.dexFileName}) -> extends ${cls.superClass} ($superDex)"
                } else null
            }.take(40)
        } else emptyList()

        return DexAnalysisBundle(
            dexFiles = summaries,
            packages = packageNodes,
            classes = allClasses,
            methods = allMethods,
            fields = allFields,
            strings = allStrings,
            crossDexReferences = crossDexRefs,
        )
    }

    /**
     * Spec-compliant DEX transformation: clears source_file_idx (sets to NO_INDEX 0xFFFFFFFF)
     * on selected class_def_items so leaking .kt/.java filenames are stripped without shifting
     * bytecode offsets, then recalculates SHA-1 (12..32) and Adler-32 (8..12).
     */
    fun stripSourceFileMetadata(
        dexBytes: ByteArray,
        targetClassDefIndices: Set<Int>,
    ): Pair<ByteArray, Int> {
        if (dexBytes.size < 112 || targetClassDefIndices.isEmpty()) return dexBytes to 0
        val out = dexBytes.copyOf()
        val buf = ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN)
        val classDefsSize = buf.getInt(96)
        val classDefsOff = buf.getInt(100)
        var modifiedCount = 0

        for (i in 0 until classDefsSize) {
            if (i !in targetClassDefIndices) continue
            val pos = classDefsOff + i * 32
            if (pos + 20 > out.size) break
            val currentSourceIdx = buf.getInt(pos + 16)
            if (currentSourceIdx != NO_INDEX) {
                buf.putInt(pos + 16, NO_INDEX)
                modifiedCount++
            }
        }

        if (modifiedCount > 0) {
            recomputeDexChecksums(out)
        }
        return out to modifiedCount
    }

    fun recomputeDexChecksums(dexBytes: ByteArray) {
        if (dexBytes.size < 32) return
        val sha1 = CryptoEngine.sha1Bytes(dexBytes.copyOfRange(32, dexBytes.size))
        System.arraycopy(sha1, 0, dexBytes, 12, 20)
        val adler = CryptoEngine.adler32(dexBytes, 12, dexBytes.size - 12).toInt()
        ByteBuffer.wrap(dexBytes).order(ByteOrder.LITTLE_ENDIAN).putInt(8, adler)
    }

    fun validateDexBytes(bytes: ByteArray): Pair<Boolean, String> {
        if (bytes.size < 112) return false to "DEX size < 112 bytes"
        val magic = String(bytes.copyOfRange(0, 8), Charsets.US_ASCII)
        if (!magic.startsWith("dex\n")) return false to "Invalid DEX magic"
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val fileSize = buf.getInt(32)
        if (fileSize != bytes.size) return false to "Header fileSize ($fileSize) != actual (${bytes.size})"
        val storedAdler = buf.getInt(8).toLong() and 0xFFFFFFFFL
        val calcAdler = CryptoEngine.adler32(bytes, 12, bytes.size - 12)
        if (storedAdler != calcAdler) return false to "Adler-32 checksum mismatch"
        val storedSha1 = bytes.copyOfRange(12, 32)
        val calcSha1 = CryptoEngine.sha1Bytes(bytes.copyOfRange(32, bytes.size))
        if (!storedSha1.contentEquals(calcSha1)) return false to "SHA-1 signature mismatch"
        return true to "DEX ${magic.substring(4, 7)} valid (Adler-32 + SHA-1 verified)"
    }

    private fun emptyErrorDex(
        fileName: String,
        size: Int,
        sha256: String,
        error: String,
        version: String = "unknown",
        adlerValid: Boolean = false,
        sha1Valid: Boolean = false,
    ): ParsedSingleDex = ParsedSingleDex(
        summary = DexFileSummary(
            fileName = fileName,
            version = version,
            isSupportedVersion = false,
            fileSizeBytes = size,
            adler32Valid = adlerValid,
            sha1Valid = sha1Valid,
            sha256Hex = sha256,
            stringCount = 0,
            typeCount = 0,
            protoCount = 0,
            fieldCount = 0,
            methodCount = 0,
            classCount = 0,
            packageCount = 0,
            compatibility = CompatibilityState.INCOMPATIBLE,
            status = ComponentStatus.INSPECTABLE,
            errorNote = error,
        ),
        classes = emptyList(),
        methods = emptyList(),
        fields = emptyList(),
        strings = emptyList(),
    )

    private fun dexOrder(name: String): Int {
        if (name == "classes.dex") return 1
        val digits = name.removePrefix("classes").removeSuffix(".dex").toIntOrNull()
        return digits ?: 999
    }

    private fun classifyString(value: String): StringSensitivity {
        val lower = value.lowercase()
        return when {
            lower.startsWith("http://") || lower.startsWith("https://") || lower.startsWith("wss://") ->
                StringSensitivity.URL_OR_ENDPOINT
            value.startsWith("AIza") || value.startsWith("sk_") || value.startsWith("pk_") ||
                lower.contains("bearer ") || lower.contains("api_key") || lower.contains("secret") ||
                lower.contains("private_key") || lower.contains("password=") ->
                StringSensitivity.POTENTIAL_SECRET_OR_KEY
            lower.startsWith("select ") || lower.startsWith("insert into ") ||
                value.contains("AES/GCM") || value.contains("AES/CBC") || value.contains("SHA-256") ->
                StringSensitivity.CRYPTO_OR_SQL
            value.contains("Class.forName") || value.contains("getDeclaredMethod") ||
                lower.contains("loadlibrary") ->
                StringSensitivity.REFLECTION_OR_JNI
            value.startsWith("L") && value.endsWith(";") -> StringSensitivity.FILE_OR_PACKAGE_REF
            else -> StringSensitivity.NORMAL
        }
    }

    private fun decodeModifiers(flags: Int, isMethod: Boolean): List<String> = buildList {
        if ((flags and ACC_PUBLIC) != 0) add("public")
        if ((flags and ACC_PRIVATE) != 0) add("private")
        if ((flags and ACC_PROTECTED) != 0) add("protected")
        if ((flags and ACC_STATIC) != 0) add("static")
        if ((flags and ACC_FINAL) != 0) add("final")
        if ((flags and ACC_ABSTRACT) != 0 && (flags and ACC_INTERFACE) == 0) add("abstract")
        if ((flags and ACC_INTERFACE) != 0) add("interface")
        if ((flags and ACC_ENUM) != 0) add("enum")
        if ((flags and ACC_ANNOTATION) != 0) add("annotation")
        if (isMethod && (flags and ACC_SYNCHRONIZED) != 0) add("synchronized")
        if (isMethod && (flags and ACC_NATIVE) != 0) add("native")
        if (isMethod && (flags and ACC_BRIDGE) != 0) add("bridge")
        if ((flags and ACC_SYNTHETIC) != 0) add("synthetic")
    }

    private fun descriptorToJavaName(desc: String): String {
        if (desc.isEmpty()) return desc
        var dims = 0
        var i = 0
        while (i < desc.length && desc[i] == '[') {
            dims++
            i++
        }
        val base = when (desc.getOrNull(i)) {
            'V' -> "void"
            'Z' -> "boolean"
            'B' -> "byte"
            'S' -> "short"
            'C' -> "char"
            'I' -> "int"
            'J' -> "long"
            'F' -> "float"
            'D' -> "double"
            'L' -> desc.substring(i + 1).removeSuffix(";").replace('/', '.')
            else -> desc
        }
        return base + "[]".repeat(dims)
    }

    private fun readUleb128(bytes: ByteArray, cursor: IntArray): Int {
        var result = 0
        var shift = 0
        var count = 0
        while (cursor[0] < bytes.size && count < 5) {
            val b = bytes[cursor[0]++].toInt() and 0xFF
            result = result or ((b and 0x7F) shl shift)
            if ((b and 0x80) == 0) break
            shift += 7
            count++
        }
        return result
    }

    private fun readMutf8String(bytes: ByteArray, offset: Int): String {
        if (offset < 0 || offset >= bytes.size) return ""
        val cursor = intArrayOf(offset)
        readUleb128(bytes, cursor) // utf16_size
        val start = cursor[0]
        var end = start
        while (end < bytes.size && bytes[end].toInt() != 0 && (end - start) < 4096) {
            end++
        }
        return String(bytes, start, end - start, Charsets.UTF_8)
    }
}
