const User = require('../models/User');
const Note = require('../models/Note');

// Admin authentication middleware
exports.authenticateAdmin = async (req, res, next) => {
    const { username, password } = req.body;
    
    // Check for hardcoded admin credentials
    if (username === 'Admin001' && password === '21CMS@51') {
        req.isAdmin = true;
        next();
    } else {
        res.status(401).json({ message: 'Invalid admin credentials' });
    }
};

// Get dashboard data
exports.getDashboardData = async (req, res) => {
    try {
        // Get all users
        const users = await User.find();
        
        // Separate teachers and students
        const teachers = users.filter(user => user.userType === 'teacher');
        const students = users.filter(user => user.userType === 'student');
        
        // Get all notes
        const notes = await Note.find();
        
        // Get notes for each teacher
        const teachersWithNotes = await Promise.all(teachers.map(async (teacher) => {
            const teacherNotes = await Note.find({ uploadedBy: teacher._id });
            return {
                fullName: teacher.fullName,
                username: teacher.username,
                email: teacher.email,
                notes: teacherNotes.map(note => ({
                    title: note.title,
                    fileName: note.fileName
                }))
            };
        }));

        // Format student data
        const formattedStudents = students.map(student => ({
            fullName: student.fullName,
            username: student.username,
            email: student.email
        }));

        // Prepare response data
        const dashboardData = {
            totalUsers: users.length,
            totalTeachers: teachers.length,
            totalStudents: students.length,
            totalNotes: notes.length,
            teachers: teachersWithNotes,
            students: formattedStudents
        };

        res.json(dashboardData);
    } catch (error) {
        console.error('Error fetching dashboard data:', error);
        res.status(500).json({ message: 'Error fetching dashboard data' });
    }
}; 