//
// Created by b on 18-11-9.
//
#include <jni.h>
#include <AndroidDef.h>
#include "MinAndroidDef.h"
#include "utils/RWGuard.h"
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sstream>
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <set>
#include <unistd.h>
#include <dirent.h>
#include <algorithm>
#include <errno.h>
# define mywrite(filename, ...) do {                                                        \
        FILE *fp = fopen(filename.c_str(), "w");                                            \
        fprintf(fp, __VA_ARGS__);                                                           \
        fflush(fp);                                                                         \
        fclose(fp);                                                                         \
    } while(false)
struct FupkInterface {
    void* reserved0;
    void* reserved1;
    void* reserved2;
    void* reserved3;
    void* reserved4;
    void* reserved5;
    void* reserved6;
    void* reserved7;
};
FupkInterface* gUpkInterface;
HashTable* userDexFiles = nullptr;
Object* (*fdvmDecodeIndirectRef)(void* self, jobject jobj) = nullptr;
Thread* (*fdvmThreadSelf)() = nullptr;
void (*fupkInvokeMethod)(const Method* meth) = nullptr;
ClassObject* (*floadClassFromDex)(DvmDex* pDvmDex,
                                  const DexClassDef* pClassDef, Object* classLoader) = nullptr;
HashTable* (*GetloadedClasses)() = nullptr;
void (*fdvmClearException)(Thread* self) = nullptr;
ClassObject* (*fdvmDefineClass)(DvmDex* pDvmDex, const char* descriptor, Object* classLoader) = nullptr;
bool (*fdvmIsClassInitialized)(const ClassObject* clazz) = nullptr;
bool (*fdvmInitClass)(ClassObject* clazz) = nullptr;
void (*frecord)(const Method* curMethod) = nullptr;

jclass dumpMethodclazz;
jmethodID useClassLoaderID;
JNIEnv* env_g;
std::string str;
std::string code_dir;
int tot_dvm;
u4 DvmName[50];
int class_sum, method_sum;
int Mode;
int userDexFilesSize() {
    return userDexFiles->tableSize;
}
u4 dvmComputeUtf8Hash(const char* utf8Str)
{
    u4 hash = 1;

    while (*utf8Str != '\0')
        hash = hash * 31 + *utf8Str++;

    return hash;
}
u4 ComputeCodeHash(const Method* curMethod) {
    DexCode *code = (DexCode *)((const u1 *)curMethod->insns - 16);
    u4 hash = 1;

    for (u4 i = 0; i < code->insnsSize; i++) {
        hash = hash * 131 + code->insns[i];
    }

    return hash;
}
void itoa(char *buf, u4 d) {
    memset(buf, 0, sizeof(buf));
    char *p = buf;
    char *p1, *p2;
    u4 ud = d;
    int divisor = 10;

    do {
        *p++ = (ud % divisor) + '0';
    }
    while (ud /= divisor);

    /* Terminate BUF.  */
    *p = 0;

    /* Reverse BUF.  */
    p1 = buf;
    p2 = p - 1;
    while (p1 < p2) {
        char tmp = *p1;
        *p1 = *p2;
        *p2 = tmp;
        p1++;
        p2--;
    }
}
DvmDex* getdvmDex(int idx, const char *&dexName) {
    if (idx >= userDexFilesSize())
        return nullptr;
    HashEntry *hashEntry = userDexFiles->pEntries + idx;
    // valid check
    if (hashEntry->data == nullptr)
        return nullptr;
    if (!RWGuard::getInstance()->isReadable(reinterpret_cast<unsigned int>(hashEntry->data))) {
        FLOGE("I Found an no empty hashEntry but it is not readable %d %08x", idx, hashEntry->data);
        return nullptr;
    }
    DvmDex *dvmDex = nullptr;
    DexOrJar *dexOrJar = (DexOrJar*) hashEntry->data;
    if (dexOrJar->isDex) {
        RawDexFile *rawDexFile = dexOrJar->pRawDexFile;
        dvmDex = rawDexFile->pDvmDex;
    } else {
        JarFile *jarFile = dexOrJar->pJarFile;
        dvmDex = jarFile->pDvmDex;
    }

    // right, just return
    dexName = dexOrJar->fileName;
    return dvmDex;
}

Object* searchClassLoader(DvmDex *pDvmDex){
    dvmHashTableLock(GetloadedClasses());
    HashTable *pHashTable = GetloadedClasses();
    HashEntry *pEntry = pHashTable->pEntries;
    // int tableSize = pHashTable->tableSize;
    int numLiveEntries = pHashTable->numEntries;
    Object *result = NULL;

    if (numLiveEntries <= 0)
    {
        FLOGE("DexDump searchClassLoader : No live entry");
        result = 0;
        goto bail;
    }

    while (numLiveEntries > 0)
    {
        if (pEntry->data != NULL && pEntry->data != HASH_TOMBSTONE)
        {
            ClassObject *pClassObject = (ClassObject*)pEntry->data;
            if(pDvmDex == pClassObject->pDvmDex){
                result = pClassObject->classLoader;
                break;
            }
            numLiveEntries--;
        }
        pEntry++;
    }
    bail:
    dvmHashTableUnlock(GetloadedClasses());
    if(result == NULL){
        FLOGE("DexDump could not find appropriate class loader");
    }
    else{
        FLOGE("DexDump select classLoader : %#x", (unsigned int)result);
    }
    return result;
}

struct arg
{
    DvmDex *pDvmDex;
    Object *loader;
} param;

char dumppath[128];
int idx = 0;
unsigned int total_mmap_len = 0;
int MAXLEN = 1024;

//历史中崩溃的类的个数 有可能为0
int crash_class_cnt;
u4 crash_class[100010];

int readDumpPath(const char* path)
{
    // FILE *fp = NULL;
    // if (dumppath[0] == 0)
    // {
    //     fp = fopen("/data/dumppath", "r");
    //     if (fp == NULL)
    //     {
    //         return 0;
    //     }

    //     fgets(dumppath, 128-1, fp);
    //     if(dumppath[strlen(dumppath) - 1] == '\n'){
    //         dumppath[strlen(dumppath) - 1] = 0;
    //     }
    //     fclose(fp);
    //     fp = NULL;
    // }
    // return 1;
    strncpy(dumppath, path, 128 - 1);
    return 1;
}

void ReadClassDataHeader(const uint8_t **pData,
                         DexClassDataHeader *pHeader)
{
    pHeader->staticFieldsSize = readUnsignedLeb128(pData);
    pHeader->instanceFieldsSize = readUnsignedLeb128(pData);
    pHeader->directMethodsSize = readUnsignedLeb128(pData);
    pHeader->virtualMethodsSize = readUnsignedLeb128(pData);
}

void ReadClassDataField(const uint8_t **pData, DexField *pField)
{
    pField->fieldIdx = readUnsignedLeb128(pData);
    pField->accessFlags = readUnsignedLeb128(pData);
}

void ReadClassDataMethod(const uint8_t **pData, DexMethod *pMethod)
{
    pMethod->methodIdx = readUnsignedLeb128(pData);
    pMethod->accessFlags = readUnsignedLeb128(pData);
    pMethod->codeOff = readUnsignedLeb128(pData);
}

//这部分代码基本是复用dexReadAndVerifyClassData中的代码
//dalvik/libdex/DexClass.cpp
DexClassData *ReadClassData(const uint8_t **pData)
{

    DexClassDataHeader header;

    if (*pData == NULL)
    {
        return NULL;
    }

    //读取classHeader数据，主要是为了获取field个数和method个数
    ReadClassDataHeader(pData, &header);

    //分配空间用于保存DexClassData
    //注意此时DexClassData中将不再用指针的形式保存数据，而是使用数组保存
    size_t resultSize = sizeof(DexClassData) + (header.staticFieldsSize * sizeof(DexField)) + (header.instanceFieldsSize * sizeof(DexField)) + (header.directMethodsSize * sizeof(DexMethod)) + (header.virtualMethodsSize * sizeof(DexMethod));

    DexClassData *result = (DexClassData *)malloc(resultSize);

    if (result == NULL)
    {
        return NULL;
    }

    uint8_t *ptr = ((uint8_t *)result) + sizeof(DexClassData);

    result->header = header;

    if (header.staticFieldsSize != 0)
    {
        result->staticFields = (DexField *)ptr;
        ptr += header.staticFieldsSize * sizeof(DexField);
    }
    else
    {
        result->staticFields = NULL;
    }

    if (header.instanceFieldsSize != 0)
    {
        result->instanceFields = (DexField *)ptr;
        ptr += header.instanceFieldsSize * sizeof(DexField);
    }
    else
    {
        result->instanceFields = NULL;
    }

    if (header.directMethodsSize != 0)
    {
        result->directMethods = (DexMethod *)ptr;
        ptr += header.directMethodsSize * sizeof(DexMethod);
    }
    else
    {
        result->directMethods = NULL;
    }

    if (header.virtualMethodsSize != 0)
    {
        result->virtualMethods = (DexMethod *)ptr;
    }
    else
    {
        result->virtualMethods = NULL;
    }

    for (uint32_t i = 0; i < header.staticFieldsSize; i++)
    {
        ReadClassDataField(pData, &result->staticFields[i]);
    }

    for (uint32_t i = 0; i < header.instanceFieldsSize; i++)
    {
        ReadClassDataField(pData, &result->instanceFields[i]);
    }

    for (uint32_t i = 0; i < header.directMethodsSize; i++)
    {
        ReadClassDataMethod(pData, &result->directMethods[i]);
    }

    for (uint32_t i = 0; i < header.virtualMethodsSize; i++)
    {
        ReadClassDataMethod(pData, &result->virtualMethods[i]);
    }

    return result;
}

void writeLeb128(uint8_t **ptr, uint32_t data)
{
    while (true)
    {
        uint8_t out = data & 0x7f;
        if (out != data)
        {
            *(*ptr)++ = out | 0x80;
            data >>= 7;
        }
        else
        {
            *(*ptr)++ = out;
            break;
        }
    }
}

uint8_t *EncodeClassData(DexClassData *pData, int &len)
{
    len = 0;

    len += unsignedLeb128Size(pData->header.staticFieldsSize);
    len += unsignedLeb128Size(pData->header.instanceFieldsSize);
    len += unsignedLeb128Size(pData->header.directMethodsSize);
    len += unsignedLeb128Size(pData->header.virtualMethodsSize);

    if (pData->staticFields)
    {
        for (uint32_t i = 0; i < pData->header.staticFieldsSize; i++)
        {
            len += unsignedLeb128Size(pData->staticFields[i].fieldIdx);
            len += unsignedLeb128Size(pData->staticFields[i].accessFlags);
        }
    }

    if (pData->instanceFields)
    {
        for (uint32_t i = 0; i < pData->header.instanceFieldsSize; i++)
        {
            len += unsignedLeb128Size(pData->instanceFields[i].fieldIdx);
            len += unsignedLeb128Size(pData->instanceFields[i].accessFlags);
        }
    }

    if (pData->directMethods)
    {
        for (uint32_t i = 0; i < pData->header.directMethodsSize; i++)
        {
            len += unsignedLeb128Size(pData->directMethods[i].methodIdx);
            len += unsignedLeb128Size(pData->directMethods[i].accessFlags);
            len += unsignedLeb128Size(pData->directMethods[i].codeOff);
        }
    }

    if (pData->virtualMethods)
    {
        for (uint32_t i = 0; i < pData->header.virtualMethodsSize; i++)
        {
            len += unsignedLeb128Size(pData->virtualMethods[i].methodIdx);
            len += unsignedLeb128Size(pData->virtualMethods[i].accessFlags);
            len += unsignedLeb128Size(pData->virtualMethods[i].codeOff);
        }
    }

    uint8_t *store = (uint8_t *)malloc(len);

    if (!store)
    {
        return NULL;
    }

    uint8_t *result = store;

    writeLeb128(&store, pData->header.staticFieldsSize);
    writeLeb128(&store, pData->header.instanceFieldsSize);
    writeLeb128(&store, pData->header.directMethodsSize);
    writeLeb128(&store, pData->header.virtualMethodsSize);

    if (pData->staticFields)
    {
        for (uint32_t i = 0; i < pData->header.staticFieldsSize; i++)
        {
            writeLeb128(&store, pData->staticFields[i].fieldIdx);
            writeLeb128(&store, pData->staticFields[i].accessFlags);
        }
    }

    if (pData->instanceFields)
    {
        for (uint32_t i = 0; i < pData->header.instanceFieldsSize; i++)
        {
            writeLeb128(&store, pData->instanceFields[i].fieldIdx);
            writeLeb128(&store, pData->instanceFields[i].accessFlags);
        }
    }

    if (pData->directMethods)
    {
        for (uint32_t i = 0; i < pData->header.directMethodsSize; i++)
        {
            writeLeb128(&store, pData->directMethods[i].methodIdx);
            writeLeb128(&store, pData->directMethods[i].accessFlags);
            writeLeb128(&store, pData->directMethods[i].codeOff);
        }
    }

    if (pData->virtualMethods)
    {
        for (uint32_t i = 0; i < pData->header.virtualMethodsSize; i++)
        {
            writeLeb128(&store, pData->virtualMethods[i].methodIdx);
            writeLeb128(&store, pData->virtualMethods[i].accessFlags);
            writeLeb128(&store, pData->virtualMethods[i].codeOff);
        }
    }

    free(pData);
    return result;
}

uint8_t *codeitem_end(const u1 **pData)
{
    uint32_t num_of_list = readUnsignedLeb128(pData);
    for (; num_of_list > 0; num_of_list--)
    {
        int32_t num_of_handlers = readSignedLeb128(pData);
        int num = num_of_handlers;
        if (num_of_handlers <= 0)
        {
            num = -num_of_handlers;
        }
        for (; num > 0; num--)
        {
            readUnsignedLeb128(pData);
            readUnsignedLeb128(pData);
        }
        if (num_of_handlers <= 0)
        {
            readUnsignedLeb128(pData);
        }
    }
    return (uint8_t *)(*pData);
}

void writeBytes(void* dst, const void* src, u4 length){
    memcpy(dst, src, length);
}


void* caculateOffsetBeforeDexData(void* ptr, DexFile* pDexFile){
    u4 string_num = pDexFile->pHeader->stringIdsSize;
    u4 type_num = pDexFile->pHeader->typeIdsSize;
    u4 proto_num = pDexFile->pHeader->protoIdsSize;
    u4 field_num = pDexFile->pHeader->fieldIdsSize;
    u4 method_num = pDexFile->pHeader->methodIdsSize;
    u4 classdef_num = pDexFile->pHeader->classDefsSize;

    u4 p = (u4)ptr + sizeof(DexHeader);
    p += sizeof(DexStringId)*string_num;
    p += sizeof(DexTypeId)*type_num;
    p += sizeof(DexProtoId)*proto_num;
    p += sizeof(DexFieldId)*field_num;
    p += sizeof(DexMethodId)*method_num;
    p += sizeof(DexClassDef)*classdef_num;

    return (void*)p;

}

// void mystrcpy(char* dst, char* src){
//     char* cur = src;
//     char* ptr = dst;
//     while(*cur != '\x00'){
//         FLOGE("mystrcpy cur at %#x : %c", (unsigned int)cur, *cur);
//         writeBytes(ptr, cur, 1);
//         cur++;
//         ptr++;
//     }
//     writeBytes(ptr, "\x00", 1);
// }

DexMapItem* DumpStringIds(void* ptr, void* &current, DexFile* pDexFile, void* &metadata_ptr){

    FLOGE("DexDump DumpStringIds start");


    u4* pStringId;
    DexMapItem* stringItem = (DexMapItem*)malloc(sizeof(DexMapItem));

    pStringId = (u4*)((u4)ptr + sizeof(DexHeader));
    u1* cur = (u1*)current;
    int num = pDexFile->pHeader->stringIdsSize;
    int i;

    for(i = 0; i < num; i++){
        const DexStringId* pOriStringId = dexGetStringId(pDexFile, i);
        const u1* tmp = pDexFile->baseAddr + pOriStringId->stringDataOff;
        strcpy((char*)cur, (char*)tmp);
        // mystrcpy((char*)cur, (char*)tmp);

        //仅在这里检查了一下是否超出mmap映射空间
        if(((unsigned int)(&(pStringId[i])) <= (unsigned int)ptr) || ((unsigned int)(&(pStringId[i])) - (unsigned int)ptr >= total_mmap_len)){
            FLOGE("DexDump bad address for pString %d", i);
            exit(0);
        }
        pStringId[i] = (u4)cur - (u4)ptr;
        cur = (u1*)((u4)cur + strlen((char*)tmp) + 1);
        if(*tmp == '\x00') cur = (u1*)((u4)cur + 1);
    }
    while(((u4)cur & 3) != 0) cur = (u1*)((u4)cur + 1);
    FLOGE("DexDump 5");

    current = (void*)cur;
    metadata_ptr = (void*)((u4)pStringId + num*sizeof(DexStringId));

    stringItem->type = kDexTypeStringIdItem;
    stringItem->size = num;
    stringItem->offset = (u4)pStringId - (u4)ptr;

    FLOGE("DexDump DumpStringIds finish");


    return stringItem;
}


DexMapItem* DumpTypeIds(void* ptr, void* &current, DexFile* pDexFile, void* &metadata_ptr){

    FLOGE("DexDump DumpTypeIds start");

    int num = pDexFile->pHeader->typeIdsSize;
    int i;
    u4* pTypeId;
    void* cur;
    DexMapItem* typeItem = (DexMapItem*)malloc(sizeof(DexMapItem));

    pTypeId = (u4*)metadata_ptr;
    cur = current;

    for(i = 0; i < num; i++){
        const DexTypeId* typeId = dexGetTypeId(pDexFile, i);
        pTypeId[i] = typeId->descriptorIdx;
    }

    current = cur;
    metadata_ptr = (void*)((u4)pTypeId + num*sizeof(DexTypeId));

    typeItem->type = kDexTypeTypeIdItem;
    typeItem->size = num;
    typeItem->offset = (u4)pTypeId - (u4)ptr;

    FLOGE("DexDump DumpTypeIds finish");

    return typeItem;
}


DexMapItem* DumpProtoIds(void* ptr, void* &current, DexFile* pDexFile, void* &metadata_ptr){

    FLOGE("DexDump DumpProtoIds start");

    int num = pDexFile->pHeader->protoIdsSize;
    int i;
    DexProtoId* pProtoId;
    void* cur;
    DexMapItem* protoItem = (DexMapItem*)malloc(sizeof(DexMapItem));

    pProtoId = (DexProtoId*)metadata_ptr;
    cur = current;

    for(i = 0; i < num; i++){
        const DexProtoId* protoId = dexGetProtoId(pDexFile, i);
        const DexTypeList* typeList = dexGetProtoParameters(pDexFile, protoId);
        if(typeList != NULL){
            pProtoId[i].parametersOff = (u4)cur - (u4)ptr;
            u4 size = typeList->size;
            writeBytes(cur, &size, 4);
            cur = (void*)((u4)cur + 4);
            for(u4 j = 0; j < size; j++){
                writeBytes(cur, &(typeList->list[j]), 2);
                cur = (void*)((u4)cur + 2);
            }
            // 根据文档要求，typelist需4字节对齐
            while(((u4)cur & 3) != 0) cur = (void*)((u4)cur + 1);
        }
        else{
            pProtoId[i].parametersOff = 0;
        }
        pProtoId[i].shortyIdx = protoId->shortyIdx;
        pProtoId[i].returnTypeIdx = protoId->returnTypeIdx;
    }

    current = cur;
    metadata_ptr = (void*)((u4)pProtoId + num*sizeof(DexProtoId));

    protoItem->type = kDexTypeProtoIdItem;
    protoItem->size = num;
    protoItem->offset = (u4)pProtoId - (u4)ptr;

    FLOGE("DexDump DumpProtoIds finish");

    return protoItem;
}

DexMapItem* DumpFieldIds(void* ptr, void* &current, DexFile* pDexFile, void* &metadata_ptr){

    FLOGE("DexDump DumpFieldIds start");


    int num = pDexFile->pHeader->fieldIdsSize;
    int i;
    DexFieldId* pFieldId;
    void* cur;
    DexMapItem* fieldItem = (DexMapItem*)malloc(sizeof(DexMapItem));

    pFieldId = (DexFieldId*)metadata_ptr;
    cur = current;

    for(i = 0; i < num; i++){
        const DexFieldId* fieldId = dexGetFieldId(pDexFile, i);
        pFieldId[i] = *fieldId;
    }

    current = cur;
    metadata_ptr = (void*)((u4)pFieldId + num*sizeof(DexFieldId));

    fieldItem->type = kDexTypeFieldIdItem;
    fieldItem->size = num;
    fieldItem->offset = (u4)pFieldId - (u4)ptr;

    FLOGE("DexDump DumpFieldIds finish");

    return fieldItem;
}

DexMapItem* DumpMethodIds(void* ptr, void* &current, DexFile* pDexFile, void* &metadata_ptr){

    FLOGE("DexDump DumpMethodIds start");

    int num = pDexFile->pHeader->methodIdsSize;
    int i;
    DexMethodId* pMethodId;
    void* cur;
    DexMapItem* methodItem = (DexMapItem*)malloc(sizeof(DexMapItem));

    pMethodId = (DexMethodId*)metadata_ptr;
    cur = current;

    for(i = 0; i < num; i++){
        const DexMethodId* methodId = dexGetMethodId(pDexFile, i);
        pMethodId[i] = *methodId;
    }

    current = cur;
    metadata_ptr = (void*)((u4)pMethodId + num*sizeof(DexMethodId));

    methodItem->type = kDexTypeMethodIdItem;
    methodItem->size = num;
    methodItem->offset = (u4)pMethodId - (u4)ptr;

    FLOGE("DexDump DumpMethodIds finish");

    return methodItem;
}

//cur指向当前需要被写入的地址
//staticDataPtr指向encoded_value[size]的起始处
u1* DumpClassStaticValue(void* &cur, u1* staticDataPtr, u4 array_size){
    enum{
        VALUE_BYTE = 0x00,
        VALUE_SHORT = 0x02,
        VALUE_CHAR = 0x03,
        VALUE_INT = 0x04,
        VALUE_LONG = 0x06,
        VALUE_FLOAT = 0x10,
        VALUE_DOUBLE = 0x11,
        VALUE_STRING = 0x17,
        VALUE_TYPE = 0x18,
        VALUE_FIELD = 0x19,
        VALUE_METHOD = 0x1a,
        VALUE_ENUM = 0x1b,
        VALUE_ARRAY = 0x1c,
        VALUE_ANNOTATION = 0x1d,
        VALUE_NULL = 0x1e,
        VALUE_BOOLEAN = 0x1f
    };
    int data_size;
    u1* newStaticDataPtr;
    u1* tmpDataPtr;
    const u1** pStream;
    u4 new_array_size, annotation_size;


    // cur will be updated
    writeLeb128((uint8_t**)&cur, array_size);

    for(u4 i = 0; i < array_size; i++){
        switch((*staticDataPtr)&0x1F){
            case VALUE_BYTE:
            case VALUE_SHORT:
            case VALUE_INT:
            case VALUE_LONG:
            case VALUE_FLOAT:
            case VALUE_DOUBLE:
            case VALUE_STRING:
            case VALUE_TYPE:
            case VALUE_FIELD:
            case VALUE_ENUM:
                data_size = (((*staticDataPtr)&0xE0)>>5) + 1;
                writeBytes(cur, staticDataPtr, data_size + 1);
                cur = (void*)((u4)cur + data_size + 1);
                staticDataPtr = (u1*)((u4)staticDataPtr + data_size + 1);
                break;

            case VALUE_ARRAY:
                newStaticDataPtr = (u1*)((u4)staticDataPtr + 1);
                pStream = (const u1**)&newStaticDataPtr;
                new_array_size = readUnsignedLeb128(pStream);
                writeBytes(cur, staticDataPtr, 1);
                cur = (void*)((u4)cur + 1);
                staticDataPtr = DumpClassStaticValue(cur, newStaticDataPtr, new_array_size);
                if(staticDataPtr == NULL){
                    return NULL;
                }
                break;

            case VALUE_ANNOTATION:
                tmpDataPtr = (u1*)((u4)staticDataPtr + 1);
                readUnsignedLeb128((const u1**)&tmpDataPtr);
                annotation_size = readUnsignedLeb128((const u1**)&tmpDataPtr);
                for(u4 j = 0; j < annotation_size; j++){
                    readUnsignedLeb128((const u1**)&tmpDataPtr);
                    tmpDataPtr++;
                }
                writeBytes(cur, staticDataPtr, (u4)staticDataPtr - (u4)tmpDataPtr);
                cur = (void*)((u4)cur + (u4)staticDataPtr - (u4)tmpDataPtr);

                staticDataPtr = tmpDataPtr;
                break;

            case VALUE_BOOLEAN:
            case VALUE_NULL:
                writeBytes(cur, staticDataPtr, 1);
                staticDataPtr++;
                cur = (void*)((u4)cur + 1);
                break;
            default:
                FLOGE("DexDump DumpClassStaticValue: Unknown type for encoded value");
                return NULL;
                break;
        }
    }

    return staticDataPtr;
}


std::string check_it(std::string ori) {

    std::string res = "";
    for (int i = 0; i < (int)ori.size(); i++) {
        if (ori[i] == '=' || ori[i] == '$' || ori[i] == '<' || ori[i] == '>' ||
            ori[i] == '|' || ori[i] == '&' || ori[i] == '(' || ori[i] == ')' ||
            ori[i] == '{' || ori[i] == '}' || ori[i] == '!') {

            res.push_back('\\');
        }
        res.push_back(ori[i]);
    }
    return res;
}
DexMapItem* DumpClass(void* ptr, void* &current, void *parament, void* &metadata_ptr) {
    /*
     *  计算我dump出的有效代码（这里指能填充回dex文件的）与jr的不同的数目
     */
    int diff_method;
    FILE *method_fp;
    if (Mode == 1) {
        std::string diff_part = std::string(dumppath) + std::string("diff.txt");
        diff_method = 0;

        method_fp = fopen(diff_part.c_str(), "w");
    }



    Thread* self = fdvmThreadSelf();
    DvmDex *pDvmDex = ((struct arg *)parament)->pDvmDex;
    Object *loader = ((struct arg *)parament)->loader;
    DexFile *pDexFile = pDvmDex->pDexFile;
    DexMapItem* classItem = (DexMapItem*)malloc(sizeof(DexMapItem));

    FLOGE("DexDump Class begin: %d ms", time);

    uint32_t mask = 0x3ffff;
    void* cur;
    DexClassDef* pClassDefRec;
    const char *header1 = "Landroid";
    const char *header2 = "Ldalvik";
    const char *header3 = "Ljava";
    const char *header4 = "Llibcore";
    const char *header5 = "Ljavax";
    const char *header6 = "Lbutterknife";
    u4 num_class_defs = pDexFile->pHeader->classDefsSize;

    pClassDefRec = (DexClassDef*)metadata_ptr;
    cur = current;

    size_t classdef_real_num = 0;
    size_t classdef_idx = 0;

    int now_crash = 1;
    class_sum = num_class_defs;

    for (u4 i = 0; i < num_class_defs; i++)
    {
        //FLOGE("DexDump : current write pointer at 0x%08x", (unsigned int)cur);
        ClassObject *clazz = NULL;
        jstring className;
        jobject ref = NULL;
        const u1 *data = NULL;
        DexClassData *pData = NULL;
        const DexClassDef *pClassDef = dexGetClassDef(pDvmDex->pDexFile, i);
        const char *descriptor = dexGetClassDescriptor(pDvmDex->pDexFile, pClassDef);

        DexClassDef temp = *pClassDef;

        bool fromrecord = 1;
        //如果是系统类，或者classDataOff为0，或者当前类位于黑名单中， 则跳过

        FLOGE("DexDump : descriptor %d : %s", i, descriptor);
        if (!strncmp(header1, descriptor, strlen(header1)) ||
            !strncmp(header2, descriptor, strlen(header2)) ||
            !strncmp(header3, descriptor, strlen(header3)) ||
            !strncmp(header4, descriptor, strlen(header4)) ||
            !strncmp(header5, descriptor, strlen(header5)) ||
            !strncmp(header6, descriptor, strlen(header6)) ||
            !pClassDef->classDataOff ||
            (now_crash <= crash_class_cnt && crash_class[now_crash] == i))
        {
            if (now_crash <= crash_class_cnt && crash_class[now_crash] == i)
                now_crash++;
            temp.classDataOff = 0;
            temp.annotationsOff = 0;
            temp.staticValuesOff = 0;
            goto interface;
        }

        FLOGE("DexDump : descriptor %s", descriptor);


        // 在这里，我们记录一下当前正在处理的类
        // 如果程序崩溃，则可以通过这种方式，将该类加入黑名单
        {
            std::string last_dump = std::string(dumppath) + std::string("last_dump");
            mywrite(last_dump, "%u\n", i);
        }

        //          here
        gUpkInterface->reserved2 = (void *) (loader);
        fdvmClearException(self);

        className = env_g->NewStringUTF(descriptor);
        ref = env_g->CallStaticObjectMethod(dumpMethodclazz, useClassLoaderID, className);
        clazz = (ClassObject *) fdvmDecodeIndirectRef(fdvmThreadSelf(), ref);

        env_g->DeleteLocalRef(className);

        //clazz = fdvmDefineClass(pDvmDex, descriptor, loader);
        // 当classLookUp抛出异常时，若没有进行处理就进入下一次lookUp，将导致dalvikAbort
        // 具体见defineClassNative中的注释
        // 这里选择直接清空exception
        fdvmClearException(self);

        if (!clazz)
        {
            FLOGE("DexDump defineClass %s failed", descriptor);
            continue;
        }

        FLOGE("DexDump class: %s", descriptor);

        //
        if (!fdvmIsClassInitialized(clazz))
        {
            if (fdvmInitClass(clazz))
            {
                FLOGE("DexDump init: %s", descriptor);
                fromrecord = 1;
            }
            else {
                fromrecord = 0;
            }
        }

        //////////////////////////////////
        ////终极杀手鐗
        //fromrecord = 0;
        ////
        //////////////////////////////////
        data = dexGetClassData(pDexFile, pClassDef);

        //返回DexClassData结构
        pData = ReadClassData(&data);


        if (!pData)
        {
            FLOGE("DexDump ReadClassData %s failed", descriptor);
            continue;
        }


        if (fromrecord == 1) {
            if (pData->directMethods) {
                method_sum += pData->header.directMethodsSize;
                for (uint32_t i = 0; i < pData->header.directMethodsSize; i++) {
                    //从clazz来获取method，这里获取到的应该是真实信息
                    Method *method = &(clazz->directMethods[i]);
                    uint32_t ac =
                            (method->accessFlags) & mask; // mask = 0x3ffff 即不会改变正常的ac，只是去掉无用的高位

                    ALOGI("DexDump direct method name %s.%s", descriptor, method->name);

                    std::string biggest_file_path;
                    s8 biggest_file_size = -1;
                    if (strcmp(method->name, "<clinit>") != 0) {
                        //先获取本地的method信息
                        DexStringCache pCache;
                        dexStringCacheInit(&pCache);
                        dexStringCacheAlloc(&pCache, 1010);
                        dexProtoGetMethodDescriptor(&(method->prototype), &pCache);

                        std::string itdir = code_dir;
                        int ln = strlen(descriptor);
                        for (int i = 0; i < ln - 1; i++) {
                            if (descriptor[i] == '/')
                                mkdir(itdir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
                            itdir.push_back(descriptor[i]);
                        }
                        mkdir(itdir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
                        itdir = itdir + std::string("/") + std::string(method->name);
                        mkdir(itdir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
                        char tmp[60];
                        u4 hashvalue = dvmComputeUtf8Hash(pCache.value);
                        itoa(tmp, hashvalue);
                        itdir = itdir + std::string("/") + std::string(tmp);
                        mkdir(itdir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
                        dexStringCacheRelease(&pCache);
                        FLOGE("DexDump direct dir's name %s", itdir.c_str());

                        /*
                         * 然后在这个目录下找到最大的已有method,这里有可能会出现
                         * 0:   直接将method更新成native，然后continue
                         * 1 或 多:   选size最大那个
                         * 多:
                         */


                        DIR *dir;
                        struct dirent *pt;

                        //std::string right_dir = check_it(itdir);
                        std::string right_dir = itdir;
                        if ((dir = opendir(itdir.c_str())) == NULL) {
                            FLOGE("ERROR : no such dir");
                            FLOGE("%s", itdir.c_str());
                            FLOGE("%s", right_dir.c_str());
                            continue;
                        }

                        FLOGE("opendir success", itdir.c_str());
                        int file_num = 0;

                        while ((pt = readdir(dir)) != NULL) {
                            if (strcmp(pt->d_name, ".") == 0 ||
                                strcmp(pt->d_name, "..") == 0)    ///current dir OR parrent dir
                                continue;


                            std::string file_path = itdir + "/" + std::string(pt->d_name);
                            struct stat statbuff;
                            stat(file_path.c_str(), &statbuff);
                            if (statbuff.st_size < 0)
                                continue;
                            else {
                                file_num++;
                                if (statbuff.st_size > biggest_file_size) {

                                    biggest_file_size = statbuff.st_size;
                                    biggest_file_path = file_path;
                                }
                            }
                        }
                        closedir(dir);
                        FLOGE("get biggest_file_path success %s", biggest_file_path.c_str());
                        if (file_num == 0 || biggest_file_size == 0) {
                            //对应着method->insns = 0 的情况
                            pData->directMethods[i].accessFlags = ac;
                            pData->directMethods[i].codeOff = 0;
                            continue;
                        }
                    }
                    //ac和dexMethod中的不符合，则需要修正
                    if (ac != pData->directMethods[i].accessFlags) {
                        ALOGI("DexDump method ac");
                        pData->directMethods[i].accessFlags = ac;
                    }

                    DexCode *code;
                    if (strcmp(method->name, "<clinit>") != 0) {
                        u1 buff[101000];

                        errno = 0;
                        FILE *fp = fopen(biggest_file_path.c_str(), "rb");
                        if (fp == NULL) {
                            FLOGE("fopen failed %d", errno);
                        }
                        int siz = fread(buff, sizeof(u1), 100000, fp);
                        FLOGE("siz = %d", siz);
                        fclose(fp);

                        code = (DexCode *) malloc(siz + 4);
                        memcpy(code, buff, siz);
                    } else {
                        FLOGE("DexDump direct method name %s.%s : 0x%08x", descriptor, method->name, (unsigned int) method->insns);
                        code = (DexCode *) ((const u1 *) method->insns - 16);
                    }

                    FLOGE("get *code success");
                    /*
                     * 比较不同
                     */
                    bool same_flag = true;

                    if (method->insns == NULL)
                        same_flag = false;
                    else {
                        DexCode *f_code = (DexCode *) ((const u1 *) method->insns - 16);
                        if (code->insnsSize != f_code->insnsSize) {
                            same_flag = false;
                        } else {
                            int diff_cnt = 0;
                            for (int k = 0; k < code->insnsSize; k++) {
                                if (code->insns[k] != f_code->insns[k]) {
                                    diff_cnt++;
                                }
                            }
                            if (diff_cnt > code->insnsSize / 5)
                                same_flag = false;
                        }
                    }

                    if (same_flag == false) {
                        diff_method++;
                        fprintf(method_fp, "%s.%s\n", descriptor, method->name);
                    }

                    pData->directMethods[i].codeOff = (u4) cur - (u4) ptr;

                    uint8_t *item = (uint8_t *) code;
                    int code_item_len = 0;
                    if (code->triesSize) {
                        const u1 *handler_data = dexGetCatchHandlerData(code);
                        const u1 **phandler = (const u1 **) &handler_data;
                        uint8_t *tail = codeitem_end(phandler);
                        code_item_len = (int) (tail - item);
                    } else {
                        code_item_len = 16 + code->insnsSize * 2;
                    }

                    writeBytes(cur, item, code_item_len);
                    ((DexCode *) cur)->debugInfoOff = 0;
                    cur = (void *) ((u4) cur + code_item_len);
                    while ((u4) cur & 3) cur = (void *) ((u4) cur + 1);

                    if (strcmp(method->name, "<clinit>") != 0) {
                        free(code);
                    }
                }
            }

            if (pData->virtualMethods) {
                method_sum += pData->header.virtualMethodsSize;
                for (uint32_t i = 0; i < pData->header.virtualMethodsSize; i++) {
                    //从clazz来获取method，这里获取到的应该是真实信息
                    Method *method = &(clazz->virtualMethods[i]);
                    uint32_t ac =
                            (method->accessFlags) & mask; // mask = 0x3ffff 即不会改变正常的ac，只是去掉无用的高位

                    ALOGI("DexDump direct method name %s.%s", descriptor, method->name);

                    //先获取本地的method信息
                    DexStringCache pCache;
                    dexStringCacheInit(&pCache);
                    dexStringCacheAlloc(&pCache, 1010);
                    dexProtoGetMethodDescriptor(&(method->prototype), &pCache);

                    std::string itdir = code_dir;
                    int ln = strlen(descriptor);
                    for (int i = 0; i < ln - 1; i++) {
                        if (descriptor[i] == '/')
                            mkdir(itdir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
                        itdir.push_back(descriptor[i]);
                    }
                    mkdir(itdir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
                    itdir = itdir + std::string("/") + std::string(method->name);
                    mkdir(itdir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
                    char tmp[60];
                    u4 hashvalue = dvmComputeUtf8Hash(pCache.value);
                    itoa(tmp, hashvalue);
                    itdir = itdir + std::string("/") + std::string(tmp);
                    mkdir(itdir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
                    dexStringCacheRelease(&pCache);
                    FLOGE("DexDump direct dir's name %s", itdir.c_str());

                    /*
                     * 然后在这个目录下找到最大的已有method,这里有可能会出现
                     * 0:   直接将method更新成native，然后continue
                     * 1 或 多:   选size最大那个
                     * 多:
                     */
                    std::string biggest_file_path;
                    s8 biggest_file_size = -1;

                    DIR *dir;
                    struct dirent *pt;

                    //std::string right_dir = check_it(itdir);
                    std::string right_dir = itdir;
                    if ((dir = opendir(itdir.c_str())) == NULL) {
                        FLOGE("ERROR : no such dir");
                        FLOGE("%s", itdir.c_str());
                        FLOGE("%s", right_dir.c_str());
                        continue;
                    }

                    FLOGE("opendir success", itdir.c_str());
                    int file_num = 0;

                    while ((pt = readdir(dir)) != NULL) {
                        if (strcmp(pt->d_name, ".") == 0 ||
                            strcmp(pt->d_name, "..") == 0)    ///current dir OR parrent dir
                            continue;


                        std::string file_path = itdir + "/" + std::string(pt->d_name);
                        struct stat statbuff;
                        stat(file_path.c_str(), &statbuff);
                        if (statbuff.st_size < 0)
                            continue;
                        else {
                            file_num++;
                            if (statbuff.st_size > biggest_file_size) {

                                biggest_file_size = statbuff.st_size;
                                biggest_file_path = file_path;
                            }
                        }
                    }
                    closedir(dir);
                    FLOGE("get biggest_file_path success %s", biggest_file_path.c_str());
                    if (file_num == 0 || biggest_file_size == 0) {
                        //对应着method->insns = 0 的情况
                        pData->virtualMethods[i].accessFlags = ac;
                        pData->virtualMethods[i].codeOff = 0;
                        continue;
                    }

                    //ac和dexMethod中的不符合，则需要修正
                    if (ac != pData->virtualMethods[i].accessFlags) {
                        ALOGI("DexDump method ac");
                        pData->virtualMethods[i].accessFlags = ac;
                    }

                    DexCode *code;
                    if (strcmp(method->name, "<clinit>") != 0) {
                        u1 buff[101000];

                        errno = 0;
                        FILE *fp = fopen(biggest_file_path.c_str(), "rb");
                        if (fp == NULL) {
                            FLOGE("fopen failed %d", errno);
                        }
                        int siz = fread(buff, sizeof(u1), 100000, fp);
                        FLOGE("siz = %d", siz);
                        fclose(fp);

                        code = (DexCode *) malloc(siz + 4);
                        memcpy(code, buff, siz);
                    } else {
                        FLOGE("DexDump virtual method name %s.%s : 0x%08x", descriptor, method->name, (unsigned int) method->insns);
                        code = (DexCode *) ((const u1 *) method->insns - 16);
                    }

                    FLOGE("get *code success");
                    /*
                     * 比较不同
                     */
                    bool same_flag = true;

                    if (method->insns == NULL)
                        same_flag = false;
                    else {
                        DexCode *f_code = (DexCode *) ((const u1 *) method->insns - 16);
                        if (code->insnsSize != f_code->insnsSize) {
                            same_flag = false;
                        } else {
                            int diff_cnt = 0;
                            for (int k = 0; k < code->insnsSize; k++) {
                                if (code->insns[k] != f_code->insns[k]) {
                                    diff_cnt++;
                                }
                            }
                            if (diff_cnt > code->insnsSize / 5)
                                same_flag = false;
                        }
                    }

                    if (same_flag == false) {
                        diff_method++;
                        fprintf(method_fp, "%s.%s\n", descriptor, method->name);
                    }

                    pData->virtualMethods[i].codeOff = (u4) cur - (u4) ptr;

                    uint8_t *item = (uint8_t *) code;
                    int code_item_len = 0;
                    if (code->triesSize) {
                        const u1 *handler_data = dexGetCatchHandlerData(code);
                        const u1 **phandler = (const u1 **) &handler_data;
                        uint8_t *tail = codeitem_end(phandler);
                        code_item_len = (int) (tail - item);
                    } else {
                        code_item_len = 16 + code->insnsSize * 2;
                    }

                    writeBytes(cur, item, code_item_len);
                    ((DexCode *) cur)->debugInfoOff = 0;
                    cur = (void *) ((u4) cur + code_item_len);
                    while ((u4) cur & 3) cur = (void *) ((u4) cur + 1);

                    if (strcmp(method->name, "<clinit>") != 0) {
                        free(code);
                    }
                }
            }
        }
        else if (fromrecord == 0) {
            if (pData->directMethods) {
                method_sum += pData->header.directMethodsSize;
                for (uint32_t i = 0; i < pData->header.directMethodsSize; i++) {
                    //从clazz来获取method，这里获取到的应该是真实信息
                    Method *method = &(clazz->directMethods[i]);
                    uint32_t ac =
                            (method->accessFlags) & mask; // mask = 0x3ffff 即不会改变正常的ac，只是去掉无用的高位

                    ALOGI("DexDump direct method name %s.%s", descriptor, method->name);

                    //method insns指针为空或者为native，但是dexMethod中codeOff不为0，则需要修正
                    if (!method->insns || ac & ACC_NATIVE) {
                        if (pData->directMethods[i].codeOff) {
                            pData->directMethods[i].accessFlags = ac;
                            pData->directMethods[i].codeOff = 0;
                        }
                        continue;
                    }

                    //ac和dexMethod中的不符合，则需要修正
                    if (ac != pData->directMethods[i].accessFlags) {
                        ALOGI("DexDump method ac");
                        pData->directMethods[i].accessFlags = ac;
                    }

                    //构造完整DexCode结构
                    pData->directMethods[i].codeOff = (u4) cur - (u4) ptr;
                    FLOGE("DexDump direct method name %s.%s : 0x%08x", descriptor, method->name, (unsigned int) method->insns);
                    DexCode *code = (DexCode *) ((const u1 *) method->insns - 16);
                    uint8_t *item = (uint8_t *) code;
                    int code_item_len = 0;
                    if (code->triesSize) {
                        const u1 *handler_data = dexGetCatchHandlerData(code);
                        const u1 **phandler = (const u1 **) &handler_data;
                        uint8_t *tail = codeitem_end(phandler);
                        code_item_len = (int) (tail - item);
                    } else {
                        code_item_len = 16 + code->insnsSize * 2;
                    }

                    writeBytes(cur, item, code_item_len);
                    ((DexCode *) cur)->debugInfoOff = 0;
                    cur = (void *) ((u4) cur + code_item_len);
                    while ((u4) cur & 3) cur = (void *) ((u4) cur + 1);
                }
            }

            if (pData->virtualMethods) {
                method_sum += pData->header.virtualMethodsSize;
                for (uint32_t i = 0; i < pData->header.virtualMethodsSize; i++) {
                    Method *method = &(clazz->virtualMethods[i]);
                    uint32_t ac = (method->accessFlags) & mask;

                    ALOGI("DexDump virtual method name %s.%s", descriptor, method->name);

                    if (!method->insns || ac & ACC_NATIVE) {
                        if (pData->virtualMethods[i].codeOff) {
                            pData->virtualMethods[i].accessFlags = ac;
                            pData->virtualMethods[i].codeOff = 0;
                        }
                        continue;
                    }

                    if (ac != pData->virtualMethods[i].accessFlags) {
                        ALOGI("DexDump method ac");
                        pData->virtualMethods[i].accessFlags = ac;
                    }

                    pData->virtualMethods[i].codeOff = (u4) cur - (u4) ptr;
                    FLOGE("DexDump virtual method name %s.%s : 0x%08x", descriptor, method->name, (unsigned int) method->insns);
                    DexCode *code = (DexCode *) ((const u1 *) method->insns - 16);
                    uint8_t *item = (uint8_t *) code;
                    int code_item_len = 0;
                    if (code->triesSize) {
                        const u1 *handler_data = dexGetCatchHandlerData(code);
                        const u1 **phandler = (const u1 **) &handler_data;
                        uint8_t *tail = codeitem_end(phandler);
                        code_item_len = (int) (tail - item);
                    } else {
                        code_item_len = 16 + code->insnsSize * 2;
                    }

                    writeBytes(cur, item, code_item_len);
                    ((DexCode *) cur)->debugInfoOff = 0;
                    cur = (void *) ((u4) cur + code_item_len);
                    while ((u4) cur & 3) cur = (void *) ((u4) cur + 1);
                }
            }
        }
        interface:
        //写入interfaceOff
        const DexTypeList* interface = dexGetInterfacesList(pDexFile, pClassDef);
        if(interface != NULL){
            temp.interfacesOff = (u4)cur - (u4)ptr;
            u4 listSize = interface->size;
            writeBytes(cur, &listSize, 4);
            cur = (void*)((u4)cur + 4);

            for(size_t k = 0; k < listSize; k++){
                writeBytes(cur, &(interface->list[k]), 2);
                cur = (void*)((u4)cur + 2);
            }
            while(((u4)cur & 3) != 0) cur = (void*)((u4)cur + 1);
        }



        if(pData != NULL){
            //写入staticValuesOff
            if(pClassDef->staticValuesOff != 0){
                //该地址如果是无效地址，则会导致内存访问错误
                u1* staticDataPtr = (u1*)((u4)pDexFile->baseAddr +  (u4)pClassDef->staticValuesOff);
                const u1** pStream = (const u1**)&staticDataPtr;
                u4 array_size = readUnsignedLeb128(pStream);

                if(pData->header.staticFieldsSize >= array_size){
                    temp.staticValuesOff = (u4)cur - (u4)ptr;
                    if(DumpClassStaticValue(cur, staticDataPtr, array_size) == NULL){
                        temp.staticValuesOff = 0;
                    }
                    while((u4)cur & 3) cur = (void*)((u4)cur + 1);
                }
                else{
                    temp.staticValuesOff = 0;
                }
            }

            //写入classData
            int class_data_len = 0;
            uint8_t *out = EncodeClassData(pData, class_data_len);
            if (!out){
                FLOGE("DexDump EncodeClassData %s failed", descriptor);
                continue;
            }

            writeBytes(cur, out, class_data_len);
            temp.classDataOff = (u4)cur - (u4)ptr;
            temp.annotationsOff = 0;
            cur = (void*)((u4)cur + class_data_len);
            while(((u4)cur & 3) != 0) cur = (void*)((u4)cur + 1);
            free(out);
            FLOGE("DexDump classdata written");
        }

        pClassDefRec[classdef_idx] = temp;
        classdef_idx++;

        if (ref != NULL) {
            env_g->DeleteLocalRef(ref);
        }
    }

    FLOGE("DexDump Class end: %d ms", time);

    classdef_real_num = classdef_idx;
    current = cur;

    classItem->type = kDexTypeClassDefItem;
    classItem->size = classdef_real_num;
    classItem->offset = (u4)pClassDefRec - (u4)ptr;

    if (Mode == 1) {
        fprintf(method_fp, "%d\n", diff_method);
        fflush(method_fp);
        fclose(method_fp);
    }
    return classItem;
}


DexMapItem* DumpDeps(void* ptr, void* &current, DexFile* pDexFile, DvmDex* pDvmDex){

    FLOGE("DexDump DumpDeps start");

    void* cur = current;
    DexMapItem* depsItem = (DexMapItem*)malloc(sizeof(DexMapItem));

    if(pDexFile->pOptHeader == NULL){
        return NULL;
    }
    u4 depsOff = pDexFile->pOptHeader->depsOffset;
    u4 depsLen = pDexFile->pOptHeader->depsLength;
    MemMapping *mem = &pDvmDex->memMap;
    void* addr = mem->addr;

    writeBytes(cur, (void*)((u4)addr + depsOff), depsLen);
    depsItem->size = depsLen;
    depsItem->offset = (u4)cur - (u4)ptr;
    cur = (void*)((u4)cur + depsLen);
    while(((u4)cur & 3) != 0) cur = (void*)((u4)cur + 1);
    current = cur;

    FLOGE("DexDump DumpDeps finish");

    return depsItem;
}

void rebuildDexFile(DexFile* pDexFile, DexMapItem* stringItem, DexMapItem* typeItem, DexMapItem* protoItem, DexMapItem* fieldItem, DexMapItem* methodItem, DexMapItem* classItem, DexMapItem* depsItem, u4 fileSize, void* ptr){

    FLOGE("DexDump rebuildDexFile start");


    char* filePath = (char*)malloc(MAXLEN);
    FILE* fp = NULL;
    char padding[64] = {0};
    u4 dexHeaderSize = sizeof(DexHeader);

    snprintf(filePath, MAXLEN-1, "%swhole.dex", dumppath);
    fp = fopen(filePath, "wb+");
    rewind(fp);

    fwrite(ptr, 1, fileSize, fp);
    fseek(fp, 0, SEEK_SET);

    if(pDexFile->pOptHeader != NULL){
        fwrite("dey\n036\x00", 1, 8, fp);
        u4 dexOffset = sizeof(DexOptHeader);
        fwrite(&dexOffset, 1, 4, fp);
        fwrite(&fileSize, 1, 4, fp);
        if(depsItem != NULL){
            fwrite(&depsItem->offset, 1, 4, fp);
            fwrite(&depsItem->size, 1, 4, fp);
            fwrite(padding, 1, 16, fp);
        }
        else{
            fwrite(padding, 1, 24, fp);
        }
    }

    fwrite("dex\n035\x00", 1, 8, fp);
    fwrite(padding, 1, 24, fp);
    fwrite(&fileSize, 1, 4, fp);
    fwrite(&dexHeaderSize, 1, 4, fp);
    fwrite(&pDexFile->pHeader->endianTag, 1, 4, fp);
    fwrite(padding, 1, 12, fp);

    fwrite(&stringItem->size, 1, 4, fp);
    fwrite(&stringItem->offset, 1, 4, fp);
    fwrite(&typeItem->size, 1, 4, fp);
    fwrite(&typeItem->offset, 1, 4, fp);
    fwrite(&protoItem->size, 1, 4, fp);
    fwrite(&protoItem->offset, 1, 4, fp);
    fwrite(&fieldItem->size, 1, 4, fp);
    fwrite(&fieldItem->offset, 1, 4, fp);
    fwrite(&methodItem->size, 1, 4, fp);
    fwrite(&methodItem->offset, 1, 4, fp);
    fwrite(&classItem->size, 1, 4, fp);
    fwrite(&classItem->offset, 1, 4, fp);

    fwrite(padding, 1, 8, fp);

    fflush(fp);
    fclose(fp);

    free(filePath);

    FLOGE("DexDump rebuildDexFile finish");

}

void addtoblacklist() {
    //从last_dump中读取最后一个类号，把它放到black_list中
    std::string last_dump = std::string(dumppath) + std::string("last_dump");
    std::string black_list = std::string(dumppath) + std::string("black_list");

    if (access(last_dump.c_str(), W_OK) != 0) {
        return;
    }

    FILE *fp;
    fp = fopen(last_dump.c_str(), "r");
    int x;
    bool succ_read;
    if (fscanf(fp, "%d", &x) == EOF)
        //不明原因崩溃
        succ_read = false;
    else
        succ_read = true;
    fclose(fp);

    if (succ_read == false)
        return;
    //清空，未了防止black_list中出现重复的类号
    fp = fopen(last_dump.c_str(), "w");
    fclose(fp);

    fp = fopen(black_list.c_str(), "a");
    fprintf(fp, "%d\n", x);
    fflush(fp);
    fclose(fp);
}
void readblacklist() {
    crash_class_cnt = 0;

    std::string black_list = std::string(dumppath) + std::string("black_list");
    if (access(black_list.c_str(), W_OK) != 0) {
        return;
    }

    FILE *fp = fopen(black_list.c_str(), "r");

    u4 x;
    while (fscanf(fp, "%u", &x) != EOF)
        crash_class[++crash_class_cnt] = x;

    std::sort(crash_class + 1, crash_class + 1 + crash_class_cnt);

    int n = 1;
    for (int i = 2; i <= crash_class_cnt; i++)  {
        if (crash_class[i] == crash_class[i - 1])
            continue;
        crash_class[++n] = crash_class[i];
    }
    crash_class_cnt = n;

    fclose(fp);
}
void dumpFromDvmDex(DvmDex* pDvmDex, Object *loader, const char* path)
{
    /*
     * path : /.../dex/num/
     */
    DexFile *pDexFile = pDvmDex->pDexFile;
    if (!readDumpPath(path))
    {
        FLOGE("DexDump read dump path failed");
        return;
    }

    addtoblacklist();
    readblacklist();
    // 用于最后写入的内存空间
    // 是否会内存不足？
    void* target_ptr;
    void* current;
    void* dex_start;
    void* metadata_ptr;

    // MemMapping *mem = &pDvmDex->memMap;
    // total_mmap_len = (unsigned int)mem->baseLength + 0x2000;
    // if(total_mmap_len < 0x20000){
    total_mmap_len = 0x5000000;
    // }
    target_ptr = mmap(NULL, total_mmap_len, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANON, -1, 0);
    if(target_ptr == MAP_FAILED){
        FLOGE("DexDump mmap failed: %s", strerror(errno));
        return;
    }

    FLOGE("DexDump mmap start: %#x %d", (unsigned int)target_ptr, idx);
    FLOGE("DexDump mmap len : %#x", total_mmap_len);
    current = target_ptr;
    if(pDexFile->pOptHeader == NULL){
        dex_start = target_ptr;
    }
    else{
        dex_start = (void*)((u4)target_ptr + sizeof(DexOptHeader));
    }

    current = caculateOffsetBeforeDexData(dex_start, pDexFile);
    metadata_ptr = NULL;
    //
    DexMapItem* stringItem = DumpStringIds(dex_start, current, pDexFile, metadata_ptr);
    DexMapItem* typeItem = DumpTypeIds(dex_start, current, pDexFile, metadata_ptr);
    DexMapItem* protoItem = DumpProtoIds(dex_start, current, pDexFile, metadata_ptr);
    DexMapItem* fieldItem = DumpFieldIds(dex_start, current, pDexFile, metadata_ptr);
    DexMapItem* methodItem = DumpMethodIds(dex_start, current, pDexFile, metadata_ptr);

    param.loader = loader;
    param.pDvmDex = pDvmDex;
    DexMapItem* classItem = DumpClass(dex_start, current, (void*)&param, metadata_ptr);
    DexMapItem* depsItem = DumpDeps(target_ptr, current, pDexFile, pDvmDex);

    rebuildDexFile(pDexFile, stringItem, typeItem, protoItem, fieldItem, methodItem, classItem, depsItem, (u4)current - (u4)target_ptr, target_ptr);

    free(stringItem);
    free(typeItem);
    free(protoItem);
    free(fieldItem);
    free(methodItem);
    free(classItem);
    if(depsItem){
        free(depsItem);
    }
    //free_log_file_related();

    if(munmap(target_ptr, total_mmap_len) == -1){
        FLOGE("DexDump munmap failed: %s", strerror(errno));
    }
    idx++;
}

void itoa(int x, char *s) {
    memset(s, 0, sizeof(s));
    int ln = 0;
    do {
        s[ln++] = '0' + x % 10;
        x /= 10;
    } while (x > 0);
}

void rebuildAll(JNIEnv* env, jobject obj, jstring folder, jint millis, jint mMode) {
    FLOGE("in rebuildAll");
    FLOGE("millis = %d, mMode = %d", (int)millis, (int)mMode);
    dumpMethodclazz = env->FindClass("android/app/fupk3/dumpMethod");
    useClassLoaderID = env->GetStaticMethodID(dumpMethodclazz, "useClassLoader", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (useClassLoaderID == NULL) {
        FLOGE("not found useClassLoaderID");
        return;
    }

    env_g = env;
    str = env->GetStringUTFChars(folder, nullptr);


    /*
     * 如果是1,则应该将记录在本地的代码补全成dex文件
     * 如果是0，则应该将直接提取
     * 顺带将tid记录到tid.txt
     */
    Mode = (int)mMode;
    if (Mode == 0) {
        str = str + std::string("/jr");
    } else {
        str = str + std::string("/101142ts");
    }
    mkdir(str.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    std::string tidFile = str + std::string("/tid.txt");
    mywrite(tidFile, "%d\n", gettid());
    sleep((int)millis);

    /*
     * 不管是哪种模式，都应该有dvmName记录每个dexfile的class数量
     */
    std::string dvmFile = str + std::string("/dvmName.txt");
    if (access(dvmFile.c_str(), W_OK) != 0) {
        //不存在这个文件，不知道要dump哪几个类
        FLOGE("ERROR : no dvmName.txt");
    }
    {
        FILE *fp = fopen(dvmFile.c_str(), "r");
        tot_dvm = 0;
        u4 classDefsSize;
        while (fscanf(fp, "%u", &classDefsSize) != EOF)
            DvmName[tot_dvm++] = classDefsSize;
        fclose(fp);
    }

    /*
     * 没有ok,说明还没有完成dump
     */
    if (Mode == 1) {
        std::string ok = str + std::string("/OK.txt");
        if (access(ok.c_str(), W_OK) != 0) {
            FLOGE("ERROR : no 101142ts code file\n");
            return;
        }
    }

    /*
     * 建立      /.../code/   目录
     * 建立对应的 /.../dex/编号/ 目录
     */
    code_dir = str + std::string("/code/");
    mkdir(code_dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    for (int i = 0; i < tot_dvm; i++) {
        std::string path;
        path = str + std::string("/dex/");

        mkdir(path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        char tmp[10]; itoa(i, tmp);
        path = path + std::string(tmp) + std::string("/");
        mkdir(path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    }


    for (int i = 0; i < tot_dvm; i++) {
        //当前个数为DvmName[i]
        FLOGE("dvmDex %d : %u", i, DvmName[i]);

        std::string path;
        path = str + std::string("/dex/");

        /*
         * 先检查  /.../dex/编号/ 目录下是否存在isdone文件，如果存在，说明已经dump完成
         *
         */
        char tmp[10];
        itoa(i, tmp);
        path = path + std::string(tmp) + std::string("/");
        std::string done = path + "isdone";
        if (access(done.c_str(), W_OK) == 0) {
            continue;
        }


        bool hasfound = false;
        for (int j = 0; j < userDexFilesSize(); j++) {
            const char *name;
            auto pDvmDex = getdvmDex(j, name);

            if (pDvmDex == nullptr) {
                continue;
            }
            FLOGE("can chos %d %u", j, pDvmDex->pDexFile->pHeader->classDefsSize);
            if (pDvmDex->pDexFile->pHeader->classDefsSize != DvmName[i])
                continue;

            Object *loader = searchClassLoader(pDvmDex);

            if (loader == NULL)
                continue;
            hasfound = true;

            class_sum = 0;
            method_sum = 0;
            dumpFromDvmDex(pDvmDex, loader, path.c_str());

            /*
             * 类个数和方法个数
             */
            mywrite(done, "%d %d\n", class_sum, method_sum);
        }
        if (hasfound == false) {
            FLOGE("ERROR : not found %d", i);
            return;
        }
    }

    std::string OK = str + std::string("/rebuild_OK.txt");
    mywrite(OK, "OK");
    return;
}
bool init() {
    bool done = false;
    auto libdvm = dlopen("libdvm.so", RTLD_NOW);
    if (libdvm == nullptr)
        goto bail;
    gUpkInterface = (FupkInterface*)dlsym(libdvm, "gFupk");
    if (gUpkInterface == nullptr)
        goto bail;
    {
        auto fn = (HashTable* (*)())dlsym(libdvm, "dvmGetUserDexFiles");
        if (fn == nullptr) {
            goto bail;
        }
        userDexFiles = fn();
    }
    GetloadedClasses = (HashTable *(*)())(dlsym(libdvm, "dvmGetLoadedClasses"));
    if (GetloadedClasses == nullptr)
        goto bail;
    fdvmDefineClass = (ClassObject *(*)(DvmDex*, const char*, Object*))(dlsym(libdvm, "_Z14dvmDefineClassP6DvmDexPKcP6Object"));
    if (fdvmDefineClass == nullptr)
        goto bail;
    fdvmIsClassInitialized = (bool (*)(const ClassObject*))(dlsym(libdvm, "_Z21dvmIsClassInitializedPK11ClassObject"));
    if (fdvmIsClassInitialized == nullptr)
        goto bail;
    fdvmInitClass = (bool (*)(ClassObject*))(dlsym(libdvm, "dvmInitClass"));
    if (fdvmInitClass == nullptr)
        goto bail;
    fdvmDecodeIndirectRef = (Object *(*)(void *, jobject))
            (dlsym(libdvm, "_Z20dvmDecodeIndirectRefP6ThreadP8_jobject"));
    if (fdvmDecodeIndirectRef == nullptr)
        goto bail;
    fdvmClearException = (void (*)(Thread*))(dlsym(libdvm, "dvmClearException"));
    if (fdvmClearException == nullptr)
        goto bail;
    fdvmThreadSelf = (Thread *(*)())(dlsym(libdvm, "_Z13dvmThreadSelfv"));
    if (fdvmThreadSelf == nullptr)
        goto bail;
    floadClassFromDex = (ClassObject* (*)(DvmDex*, const DexClassDef*, Object*))dlsym(libdvm, "loadClassFromDex");
    if (floadClassFromDex == nullptr)
        goto bail;
    frecord = (void (*)(const Method* curMethod))dlsym(libdvm, "_Z6recordPK6Method");
    if (frecord == nullptr)
        goto bail;

    done = true;

    bail:
    if (!done) {
        FLOGE("Unable to initlize are you sure you are run in the correct machine");
    }
    return done;
}
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved)
{
    FLOGE("try to load rebuild");
    JNIEnv *env = nullptr;
    jint result = -1;


    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        //FLOGE("This jni version is not supported");
        return JNI_VERSION_1_6;
    }

    auto clazz = env->FindClass("android/app/fupk3/Rbd");

    JNINativeMethod natives[] = {
            {"rebuildAll", "(Ljava/lang/String;II)V", (void*)rebuildAll}
    };
    if (env->RegisterNatives(clazz, natives,
                             sizeof(natives)/sizeof(JNINativeMethod)) != JNI_OK) {
        env->ExceptionClear();
    }
    FLOGE("rebuild load success");

    if (init())
        FLOGE("init success");

    return JNI_VERSION_1_6;
}



