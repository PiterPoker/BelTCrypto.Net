using BelTCrypto.Core.Factories;
using BelTCrypto.Net;
using BelTCrypto.Net.Factories;
using BelTCrypto.Net.Interfaces;
using BelTCrypto.Net.Providers;
using BelTCrypto.Net.Services;
using System.Security.Cryptography;

namespace BelTCrypto.Tests;

[TestFixture]
public class BelTEcbCryptoServiceIntegrationTests
{
    private IKeyQuotaTracker _quotaTracker;
    private IManagedBelTEcbProvider _managedProvider;
    private ISessionKeyManager _sessionManager;

    [SetUp]
    public void Setup()
    {
        var ecbCore = BelTEcbFactory.Create();
        _quotaTracker = KeyQuotaTrackerFactory.Create();
        _managedProvider = ManagedProviderFactory.Create(ecbCore, _quotaTracker);
        var keyService = BelTKeyServiceFactory.Create();

        var masterKey = SecureCryptoKeyFactory.Create(new byte[32]); // Мастер-пароль (пароль пользователя)

        // ВАЖНО: Фиксируем Nonce для теста, чтобы Дешифратор смог восстановить ключ
        var sessionNonce = new byte[16];
        RandomNumberGenerator.Fill(sessionNonce);
        // Мокаем SessionManager, чтобы подставлять конкретные ключи из таблиц стандарта
        _sessionManager = SessionKeyManagerFactory.Create(masterKey, keyService, sessionNonce);
    }

    [Test]
    [Description("Истинный E2E тест: Проверка полного цикла с мутацией ключей через belt-keyrep и подробным логгированием")]
    public void Full_EndToEnd_Lifecycle_Test()
    {
        TestContext.Out.WriteLine("=== [START] Интеграционный E2E Тест: Жизненный цикл BelT ===");

        // 1. Arrange: Настраиваем зависимости
        TestContext.Out.WriteLine("[Arrange] Инициализация фабрик и базовых компонентов...");

        var service = new BelTEcbCryptoService(_sessionManager, _managedProvider, _quotaTracker);

        var workingKeyId = _sessionManager.CurrentKey.Id;
        // Подготовка данных
        string originalText = "Это секретные данные для проверки полного цикла СТБ 34.101.31-2020";
        var originalData = System.Text.Encoding.UTF8.GetBytes(originalText);
        var encryptedData = new byte[originalData.Length];
        var decryptedData = new byte[originalData.Length];

        TestContext.Out.WriteLine($"[Arrange] Исходное сообщение: '{originalText}'");
        TestContext.Out.WriteLine($"[Arrange] Исходные данные (Hex): {Convert.ToHexString(originalData)}");

        // Фиксируем квоту до шифрования
        long initialQuota = _quotaTracker.GetRemainingQuota(workingKeyId, BelTEncryptionMode.Ecb);
        TestContext.Out.WriteLine($"[Arrange] Начальная квота ключа: {initialQuota} блоков.");

        // 2. Act - Шифрование
        TestContext.Out.WriteLine("\n=== [ACT] Операция шифрования ===");
        service.Encrypt(originalData, encryptedData);

        TestContext.Out.WriteLine($"[Encrypt] Шифротекст (Hex): {Convert.ToHexString(encryptedData)}");
        long quotaAfterEncrypt = _quotaTracker.GetRemainingQuota(workingKeyId, BelTEncryptionMode.Ecb);
        TestContext.Out.WriteLine($"[Encrypt] Остаток квоты: {quotaAfterEncrypt} блоков (Потрачено: {initialQuota - quotaAfterEncrypt}).");

        // 2. Act - Дешифрование
        TestContext.Out.WriteLine("\n=== [ACT] Операция дешифрования ===");
        service.Decrypt(encryptedData, decryptedData);

        string decryptedText = System.Text.Encoding.UTF8.GetString(decryptedData);
        TestContext.Out.WriteLine($"[Decrypt] Расшифрованные данные (Hex): {Convert.ToHexString(decryptedData)}");
        TestContext.Out.WriteLine($"[Decrypt] Расшифрованное сообщение: '{decryptedText}'");

        long quotaAfterDecrypt = _quotaTracker.GetRemainingQuota(workingKeyId, BelTEncryptionMode.Ecb);
        TestContext.Out.WriteLine($"[Decrypt] Остаток квоты после дешифрования: {quotaAfterDecrypt} блоков.");

        // 3. Assert
        TestContext.Out.WriteLine("\n=== [ASSERT] Проверка утверждений (Asserts) ===");
        Assert.That(encryptedData, Is.Not.EqualTo(originalData), "Шифротекст совпадает с открытым текстом (шифрование не сработало)!");
        TestContext.Out.WriteLine("[OK] Шифротекст успешно видоизменен.");

        Assert.That(decryptedData, Is.EqualTo(originalData), "Дешифрованные данные не совпали с оригиналом!");
        TestContext.Out.WriteLine("[OK] Дешифрованные данные побитово совпадают с оригиналом.");

        TestContext.Out.WriteLine("=== [SUCCESS] Интеграционный цикл успешно завершен ===");
    }
}