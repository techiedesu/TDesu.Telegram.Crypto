namespace TDesu.Crypto.Tests

open NUnit.Framework
open TDesu.Crypto
open TDesu.Crypto.Tests

[<TestFixture>]
type KeyDerivationTests() =

    [<Test>]
    member _.``computeMsgKey returns 16 bytes``() =
        let authKey = Array.init 256 (fun i -> byte i)
        let plaintext = Array.init 64 (fun i -> byte (i * 2))
        let msgKey = KeyDerivation.computeMsgKey authKey plaintext 0
        equals msgKey.Length 16

    [<Test>]
    member _.``deriveAesKeyIv returns correct sizes``() =
        let authKey = Array.init 256 (fun i -> byte i)
        let msgKey = Array.init 16 (fun i -> byte i)
        let result = KeyDerivation.deriveAesKeyIv authKey msgKey 0
        equals result.Key.Length 32
        equals result.Iv.Length 32

    [<Test>]
    member _.``Client and server derive different keys``() =
        let authKey = Array.init 256 (fun i -> byte i)
        let msgKey = Array.init 16 (fun i -> byte i)
        let clientKeys = KeyDerivation.deriveAesKeyIv authKey msgKey 0
        let serverKeys = KeyDerivation.deriveAesKeyIv authKey msgKey 8
        notEquals clientKeys.Key serverKeys.Key
        notEquals clientKeys.Iv serverKeys.Iv

    [<Test>]
    member _.``Same inputs produce same output``() =
        let authKey = Array.init 256 (fun i -> byte i)
        let plaintext = Array.init 64 (fun i -> byte (i * 2))
        let msgKey1 = KeyDerivation.computeMsgKey authKey plaintext 0
        let msgKey2 = KeyDerivation.computeMsgKey authKey plaintext 0
        equals msgKey1 msgKey2

    /// Regression pin, not an independent oracle: there is no smaller published
    /// MTProto vector for this construction than a full DC handshake, so these
    /// outputs were computed once from the pre-refactor implementation for these
    /// exact inputs and hardcoded here. The point is not that these bytes are
    /// independently known-correct — it's that a refactor of the six slice offsets
    /// this function reads (the audit's own description of what makes this code
    /// risky to touch without an oracle) must keep reproducing them exactly.
    [<Test>]
    member _.``deriveAesKeyIv and computeMsgKey match a pinned regression vector``() =
        let authKey = Array.init 256 (fun i -> byte i)
        let msgKey = Array.init 16 (fun i -> byte i)
        let plaintext = Array.init 64 (fun i -> byte (i * 2))

        let client = KeyDerivation.deriveAesKeyIv authKey msgKey 0
        let server = KeyDerivation.deriveAesKeyIv authKey msgKey 8
        let computedMsgKey = KeyDerivation.computeMsgKey authKey plaintext 0

        equals client.Key (Rsa.hexToBytes "704ED09C8B41668AE8F99D244738F71DBDDC44469B6BBD4AA8573DD042BD059E")
        equals client.Iv (Rsa.hexToBytes "4D266000A550EDABBF4C7CE40FD0043CC92230184CD317A5CC9C2482FD3B9318")
        equals server.Key (Rsa.hexToBytes "217725799B245806458174A1FCFBC883906807B15033FDD0EA2B4D69CF9C364E")
        equals server.Iv (Rsa.hexToBytes "669A6538917A4FA56CA32360A431C9160BE4AD887140980DAB91CE7BDC47FFBC")
        equals computedMsgKey (Rsa.hexToBytes "6678B24BFA8A400001DEDFD534F797F8")
