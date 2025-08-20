document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('token');
    const user = JSON.parse(localStorage.getItem('user'));
    const currentPage = window.location.pathname.split('/').pop() || 'index.html';

    if (!token && currentPage !== 'login.html' && currentPage !== 'register.html') {
        window.location.href = 'login.html';
        return;
    }

    if (user) {
        const userInfo = document.getElementById('userInfo');
        const logoutBtn = document.getElementById('logoutBtn');
        if (userInfo && logoutBtn) {
            userInfo.textContent = `Logged in as: ${user.name} (${user.email})`;
            logoutBtn.style.display = 'inline';
        }
        if (user.isAdmin && currentPage === 'index.html') {
            const adminBtn = document.getElementById('adminBtn');
            if (adminBtn) adminBtn.style.display = 'inline';
        }
    }

    if (currentPage === 'index.html') {
        if (user && user.isAdmin) {
            window.location.href = 'admin.html';
            return;
        }
        fetchProfile();
    } else if (currentPage === 'admin.html') {
        if (!user || !user.isAdmin) {
            window.location.href = 'index.html';
            return;
        }
        fetchUsers();
    }
});

function goToAdminPage() {
    window.location.href = 'admin.html';
}

function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = 'login.html';
}

async function fetchProfile() {
    const token = localStorage.getItem('token');
    const response = await fetch('http://127.0.0.1:5000/profile', {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    if (response.status === 401) {
        alert('Session expired. Please log in again.');
        logout();
        return;
    }
    if (!response.ok) {
        const error = await response.json();
        alert(error.error);
        return;
    }
    const user = await response.json();
    document.getElementById('userId').value = user._id;
    document.getElementById('userName').value = user.name;
    document.getElementById('userEmail').value = user.email;
    document.getElementById('profileName').textContent = user.name;
    document.getElementById('profileEmail').textContent = user.email;
}

async function updateProfile() {
    const token = localStorage.getItem('token');
    const id = document.getElementById('userId').value;
    const name = document.getElementById('userName').value;
    const email = document.getElementById('userEmail').value;

    if (!name || !email) {
        alert('Please fill in all fields');
        return;
    }

    const response = await fetch('http://127.0.0.1:5000/profile', {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ name, email })
    });
    if (response.status === 401) {
        alert('Session expired. Please log in again.');
        logout();
        return;
    }
    if (!response.ok) {
        const error = await response.json();
        alert(error.error);
        return;
    }
    const updatedUser = await response.json();
    localStorage.setItem('user', JSON.stringify({ name: updatedUser.name, email: updatedUser.email, isAdmin: JSON.parse(localStorage.getItem('user')).isAdmin }));
    fetchProfile();
}

async function fetchUsers() {
    const token = localStorage.getItem('token');
    const response = await fetch('http://127.0.0.1:5000/users', {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    if (response.status === 401 || response.status === 403) {
        alert('Admin access required or session expired. Please log in again.');
        logout();
        return;
    }
    if (!response.ok) {
        const error = await response.json();
        alert(error.error);
        return;
    }
    const users = await response.json();
    const tableBody = document.getElementById('userTableBody');
    tableBody.innerHTML = '';
    users.forEach(user => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${user.name}</td>
            <td>${user.email}</td>
            <td>${user.isAdmin ? 'Admin' : 'User'}</td>
            <td class="action-buttons">
                <button class="edit-btn" onclick="editUser('${user._id}', '${user.name}', '${user.email}', ${user.isAdmin})">Edit</button>
                <button class="delete-btn" onclick="deleteUser('${user._id}')">Delete</button>
                <button class="password-btn" onclick="openPasswordModal('${user._id}')">Change Password</button>
            </td>
        `;
        tableBody.appendChild(row);
    });
}

async function saveUser() {
    const token = localStorage.getItem('token');
    const id = document.getElementById('userId').value;
    const name = document.getElementById('userName').value;
    const email = document.getElementById('userEmail').value;
    const isAdmin = document.getElementById('userRole').value === 'true';

    if (!name || !email) {
        alert('Please fill in all fields');
        return;
    }

    const method = id ? 'PUT' : 'POST';
    const url = id ? `http://127.0.0.1:5000/users/${id}` : 'http://127.0.0.1:5000/users';
    const response = await fetch(url, {
        method: method,
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ name, email, isAdmin })
    });
    if (response.status === 401 || response.status === 403) {
        alert('Admin access required or session expired. Please log in again.');
        logout();
        return;
    }
    if (!response.ok) {
        const error = await response.json();
        alert(error.error);
        return;
    }
    resetForm();
    fetchUsers();
}

function editUser(id, name, email, isAdmin) {
    document.getElementById('userId').value = id;
    document.getElementById('userName').value = name;
    document.getElementById('userEmail').value = email;
    document.getElementById('userRole').value = isAdmin.toString();
}

async function deleteUser(id) {
    const token = localStorage.getItem('token');
    if (confirm('Are you sure you want to delete this user?')) {
        const response = await fetch(`http://127.0.0.1:5000/users/${id}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (response.status === 401 || response.status === 403) {
            alert('Admin access required or session expired. Please log in again.');
            logout();
            return;
        }
        if (!response.ok) {
            const error = await response.json();
            alert(error.error);
            return;
        }
        fetchUsers();
    }
}

function openPasswordModal(userId) {
    document.getElementById('modalUserId').value = userId;
    document.getElementById('newPassword').value = '';
    document.getElementById('passwordModal').style.display = 'block';
}

function closeModal() {
    document.getElementById('passwordModal').style.display = 'none';
}

async function changePassword() {
    const token = localStorage.getItem('token');
    const userId = document.getElementById('modalUserId').value;
    const newPassword = document.getElementById('newPassword').value;

    if (!newPassword) {
        alert('Please enter a new password');
        return;
    }

    const response = await fetch(`http://127.0.0.1:5000/users/${userId}/password`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ new_password: newPassword })
    });

    if (response.status === 401 || response.status === 403) {
        alert('Admin access required or session expired. Please log in again.');
        logout();
        return;
    }
    if (!response.ok) {
        const error = await response.json();
        alert(error.error);
        return;
    }

    alert('Password updated successfully');
    closeModal();
}

async function login() {
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    if (!email || !password) {
        alert('Please fill in all fields');
        return;
    }

    const response = await fetch('http://127.0.0.1:5000/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
    });

    if (!response.ok) {
        const error = await response.json();
        alert(error.error);
        return;
    }

    const data = await response.json();
    localStorage.setItem('token', data.token);
    localStorage.setItem('user', JSON.stringify({ name: data.name, email: data.email, isAdmin: data.isAdmin }));
    window.location.href = data.isAdmin ? 'admin.html' : 'index.html';
}

async function register() {
    const name = document.getElementById('name').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    if (!name || !email || !password) {
        alert('Please fill in all fields');
        return;
    }

    const response = await fetch('http://127.0.0.1:5000/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password })
    });

    if (!response.ok) {
        const error = await response.json();
        alert(error.error);
        return;
    }

    const data = await response.json();
    localStorage.setItem('token', data.token);
    localStorage.setItem('user', JSON.stringify({ name: data.name, email: data.email, isAdmin: data.isAdmin }));
    window.location.href = data.isAdmin ? 'admin.html' : 'index.html';
}

function resetForm() {
    const formFields = ['userId', 'userName', 'userEmail', 'userRole'];
    formFields.forEach(field => {
        const element = document.getElementById(field);
        if (element) element.value = field === 'userRole' ? 'false' : '';
    });
}