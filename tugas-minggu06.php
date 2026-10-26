<?php
session_start();

// Penyimpanan sementara menggunakan session
if (!isset($_SESSION['users'])) {
    $_SESSION['users'] = [];
}

if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$errors = [];
$success = '';
$editId = null;

$old = [
    'nama' => '',
    'email' => '',
    'username' => ''
];

// Fungsi untuk mencegah XSS
function e($value) {
    return htmlspecialchars(
        (string) $value,
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    );
}

// Ambil data yang akan diedit
if (isset($_GET['edit'])) {
    $editId = (int) $_GET['edit'];

    if (isset($_SESSION['users'][$editId])) {
        $user = $_SESSION['users'][$editId];

        $old = [
            'nama' => $user['nama'],
            'email' => $user['email'],
            'username' => $user['username']
        ];
    } else {
        $editId = null;
    }
}

// Proses form
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $old = [
        'nama' => trim($_POST['nama'] ?? ''),
        'email' => trim($_POST['email'] ?? ''),
        'username' => trim($_POST['username'] ?? '')
    ];

    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['konfirmasi_password'] ?? '';
    $id = isset($_POST['id']) && $_POST['id'] !== ''
        ? (int) $_POST['id']
        : null;

    $isEdit = $id !== null;

    // Validasi token CSRF
    if (
        !isset($_POST['csrf_token']) ||
        !hash_equals(
            $_SESSION['csrf_token'],
            $_POST['csrf_token']
        )
    ) {
        $errors[] = 'Permintaan tidak valid. Silakan muat ulang halaman.';
    }

    // Validasi nama lengkap
    if ($old['nama'] === '') {
        $errors[] = 'Nama lengkap wajib diisi.';
    } elseif (mb_strlen($old['nama']) < 3) {
        $errors[] = 'Nama lengkap minimal 3 karakter.';
    }

    // Validasi email
    if (!filter_var($old['email'], FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Format alamat email tidak valid.';
    }

    // Validasi username
    if (!preg_match('/^[a-zA-Z0-9_]{4,20}$/', $old['username'])) {
        $errors[] = 'Username harus 4-20 karakter, hanya huruf, angka, dan underscore.';
    }

    // Pastikan data edit memang tersedia
    if ($isEdit && !isset($_SESSION['users'][$id])) {
        $errors[] = 'Data yang ingin diedit tidak ditemukan.';
    }

    // Username dan email harus unik
    foreach ($_SESSION['users'] as $existingId => $existingUser) {
        if ($isEdit && $existingId === $id) {
            continue;
        }

        if (strcasecmp(
            $existingUser['username'],
            $old['username']
        ) === 0) {
            $errors[] = 'Username sudah digunakan.';
            break;
        }
    }

    foreach ($_SESSION['users'] as $existingId => $existingUser) {
        if ($isEdit && $existingId === $id) {
            continue;
        }

        if (strcasecmp(
            $existingUser['email'],
            $old['email']
        ) === 0) {
            $errors[] = 'Alamat email sudah terdaftar.';
            break;
        }
    }

    // Validasi password
    if (!$isEdit && $password === '') {
        $errors[] = 'Password wajib diisi.';
    }

    if ($password !== '' && strlen($password) < 8) {
        $errors[] = 'Password minimal 8 karakter.';
    }

    if ($password !== $confirmPassword) {
        $errors[] = 'Konfirmasi password tidak cocok.';
    }

    // Simpan data apabila validasi berhasil
    if (empty($errors)) {
        if ($isEdit) {
            $_SESSION['users'][$id]['nama'] = $old['nama'];
            $_SESSION['users'][$id]['email'] = $old['email'];
            $_SESSION['users'][$id]['username'] = $old['username'];

            // Password lama dipertahankan jika tidak diubah
            if ($password !== '') {
                $_SESSION['users'][$id]['password'] =
                    password_hash($password, PASSWORD_DEFAULT);
            }

            $success = 'Data pengguna berhasil diperbarui.';
        } else {
            $newId = empty($_SESSION['users'])
                ? 1
                : max(array_keys($_SESSION['users'])) + 1;

            $_SESSION['users'][$newId] = [
                'nama' => $old['nama'],
                'email' => $old['email'],
                'username' => $old['username'],
                'password' => password_hash(
                    $password,
                    PASSWORD_DEFAULT
                )
            ];

            $success = 'Registrasi berhasil disimpan.';
        }

        // Mencegah pengiriman ulang form saat refresh
        $_SESSION['flash'] = $success;
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
        exit;
    }

    $editId = $isEdit ? $id : null;
}

// Pesan setelah redirect
if (isset($_SESSION['flash'])) {
    $success = $_SESSION['flash'];
    unset($_SESSION['flash']);
}

// Proses hapus data dengan POST dan CSRF
if (
    $_SERVER['REQUEST_METHOD'] === 'POST' &&
    isset($_POST['hapus_id'])
) {
    // Bagian ini dapat dipindahkan ke atas blok
    // pemrosesan registrasi agar aksi hapus diproses dahulu.
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registrasi Pengguna</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            padding: 35px 16px;
            background: #f1f5f9;
            color: #1e293b;
            font-family: Arial, sans-serif;
        }

        .container {
            max-width: 950px;
            margin: auto;
        }

        .header {
            text-align: center;
            margin-bottom: 25px;
        }

        .header h1 {
            color: #2563eb;
            margin-bottom: 8px;
        }

        .header p {
            color: #64748b;
        }

        .card {
            background: white;
            padding: 28px;
            border-radius: 16px;
            box-shadow: 0 8px 25px rgba(15, 23, 42, .08);
            margin-bottom: 25px;
        }

        h2 {
            margin-top: 0;
            font-size: 21px;
        }

        .form-group {
            margin-bottom: 18px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            font-weight: bold;
        }

        input {
            width: 100%;
            padding: 12px;
            border: 1px solid #cbd5e1;
            border-radius: 8px;
            font-size: 15px;
        }

        input:focus {
            outline: 2px solid #bfdbfe;
            border-color: #2563eb;
        }

        .hint {
            color: #64748b;
            font-size: 12px;
            margin-top: 6px;
        }

        button, .btn {
            display: inline-block;
            border: 0;
            border-radius: 8px;
            padding: 11px 16px;
            cursor: pointer;
            text-decoration: none;
            font-size: 14px;
            font-weight: bold;
        }

        .primary {
            color: white;
            background: #2563eb;
        }

        .primary:hover {
            background: #1d4ed8;
        }

        .secondary {
            color: #334155;
            background: #e2e8f0;
        }

        .edit {
            background: #fef3c7;
            color: #92400e;
        }

        .danger {
            background: #fee2e2;
            color: #b91c1c;
        }

        .alert {
            padding: 13px 16px;
            border-radius: 8px;
            margin-bottom: 18px;
        }

        .alert-success {
            color: #166534;
            background: #dcfce7;
        }

        .alert-error {
            color: #991b1b;
            background: #fee2e2;
        }

        .alert-error ul {
            margin-bottom: 0;
        }

        .table-wrap {
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 580px;
        }

        th, td {
            padding: 13px 10px;
            border-bottom: 1px solid #e2e8f0;
            text-align: left;
        }

        th {
            background: #eff6ff;
        }

        .actions {
            display: flex;
            gap: 7px;
            align-items: center;
        }

        .actions form {
            margin: 0;
        }

        .empty {
            text-align: center;
            color: #64748b;
            padding: 25px;
        }

        .footer {
            text-align: center;
            font-size: 13px;
            color: #64748b;
        }

        @media (max-width: 600px) {
            .card {
                padding: 20px 16px;
            }

            .header h1 {
                font-size: 25px;
            }
        }
    </style>
</head>
<body>
<div class="container">

    <header class="header">
        <h1>Registrasi Pengguna</h1>
        <p>Silakan isi formulir untuk mendaftarkan akun baru.</p>
    </header>

    <section class="card">
        <h2>
            <?= $editId !== null
                ? 'Edit Data Pengguna'
                : 'Form Registrasi' ?>
        </h2>

        <?php if ($success !== ''): ?>
            <div class="alert alert-success">
                <?= e($success) ?>
            </div>
        <?php endif; ?>

        <?php if (!empty($errors)): ?>
            <div class="alert alert-error">
                <strong>Periksa kembali formulir:</strong>
                <ul>
                    <?php foreach ($errors as $error): ?>
                        <li><?= e($error) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <form method="POST" action="" id="registrationForm">
            <input
                type="hidden"
                name="csrf_token"
                value="<?= e($_SESSION['csrf_token']) ?>"
            >

            <input
                type="hidden"
                name="id"
                value="<?= $editId !== null ? (int) $editId : '' ?>"
            >

            <div class="form-group">
                <label for="nama">Nama Lengkap</label>
                <input
                    type="text"
                    id="nama"
                    name="nama"
                    value="<?= e($old['nama']) ?>"
                    minlength="3"
                    maxlength="100"
                    autocomplete="name"
                    required
                >
            </div>

            <div class="form-group">
                <label for="email">Alamat Email</label>
                <input
                    type="email"
                    id="email"
                    name="email"
                    value="<?= e($old['email']) ?>"
                    maxlength="254"
                    autocomplete="email"
                    required
                >
            </div>

            <div class="form-group">
                <label for="username">Username</label>
                <input
                    type="text"
                    id="username"
                    name="username"
                    value="<?= e($old['username']) ?>"
                    minlength="4"
                    maxlength="20"
                    pattern="[a-zA-Z0-9_]{4,20}"
                    autocomplete="username"
                    required
                >
                <p class="hint">
                    4-20 karakter, gunakan huruf, angka, atau underscore.
                </p>
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input
                    type="password"
                    id="password"
                    name="password"
                    minlength="8"
                    autocomplete="<?= $editId !== null
                        ? 'new-password'
                        : 'new-password' ?>"
                    <?= $editId === null ? 'required' : '' ?>
                >
                <?php if ($editId !== null): ?>
                    <p class="hint">
                        Kosongkan jika ingin mempertahankan password lama.
                    </p>
                <?php else: ?>
                    <p class="hint">Minimal 8 karakter.</p>
                <?php endif; ?>
            </div>

            <div class="form-group">
                <label for="konfirmasi_password">
                    Konfirmasi Password
                </label>
                <input
                    type="password"
                    id="konfirmasi_password"
                    name="konfirmasi_password"
                    minlength="8"
                    autocomplete="new-password"
                    <?= $editId === null ? 'required' : '' ?>
                >
            </div>

            <button type="submit" class="primary">
                <?= $editId !== null
                    ? 'Simpan Perubahan'
                    : 'Daftar Sekarang' ?>
            </button>

            <?php if ($editId !== null): ?>
                <a href="<?= e(strtok($_SERVER['REQUEST_URI'], '?')) ?>"
                   class="btn secondary">
                    Batal
                </a>
            <?php endif; ?>
        </form>
    </section>

    <section class="card">
        <h2>Data Pengguna Terdaftar</h2>

        <?php if (empty($_SESSION['users'])): ?>
            <div class="empty">
                Belum ada pengguna yang terdaftar.
            </div>
        <?php else: ?>
            <div class="table-wrap">
                <table>
                    <thead>
                    <tr>
                        <th>No.</th>
                        <th>Nama Lengkap</th>
                        <th>Email</th>
                        <th>Username</th>
                        <th>Aksi</th>
                    </tr>
                    </thead>
                    <tbody>
                    <?php $no = 1; ?>
                    <?php foreach ($_SESSION['users'] as $id => $user): ?>
                        <tr>
                            <td><?= $no++ ?></td>
                            <td><?= e($user['nama']) ?></td>
                            <td><?= e($user['email']) ?></td>
                            <td><?= e($user['username']) ?></td>
                            <td>
                                <div class="actions">
                                    <a
                                        class="btn edit"
                                        href="?edit=<?= (int) $id ?>"
                                    >Edit</a>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </section>

    <footer class="footer">
        <p>Tugas Minggu 06 &mdash; Pemrograman PHP</p>
    </footer>

</div>

<script>
    const form = document.getElementById('registrationForm');
    const password = document.getElementById('password');
    const confirmPassword =
        document.getElementById('konfirmasi_password');

    form.addEventListener('submit', function (event) {
        if (password.value !== confirmPassword.value) {
            event.preventDefault();
            confirmPassword.setCustomValidity(
                'Konfirmasi password tidak cocok.'
            );
            confirmPassword.reportValidity();
        } else {
            confirmPassword.setCustomValidity('');
        }
    });

    confirmPassword.addEventListener('input', function () {
        confirmPassword.setCustomValidity('');
    });
</script>
</body>
</html>
