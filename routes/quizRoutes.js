const express = require('express');
const router = express.Router();
const pool = require('../config/database');
const quizzes = require('../data/quizzes');

// Endpoint to get quizzes available for a specific user
router.get('/quizzes', async (req, res) => {
  const { user_id } = req.query; // User ID ko query se le rahe hain
  if (!user_id) return res.status(400).json({ error: 'User ID required' });

  let connection;
  try {
    connection = await pool.getConnection(); // DB connection le rahe hain
    await connection.beginTransaction(); // Transaction start kar rahe hain

    // User ke current level ko fetch kar rahe hain
    const [userRows] = await connection.query('SELECT current_level FROM users WHERE user_id = ?', [user_id]);
    if (!userRows.length) {
      await connection.rollback(); // Agar user nahi milta to rollback kar rahe hain
      return res.status(404).json({ error: 'User not found' });
    }
    let currentLevel = userRows[0].current_level;

    // Quizzes ko filter kar rahe hain, jo current level ke liye available hain
    const levelQuizIds = quizzes.filter(q => q.level === currentLevel).map(q => q.quiz_id);
    if (levelQuizIds.length > 0) {
      // User ne kaunse quizzes complete kiye hain, wo check kar rahe hain
      const [completedCount] = await connection.query(
        'SELECT COUNT(DISTINCT quiz_id) AS count FROM user_quiz_progress WHERE user_id = ? AND quiz_id IN (?) AND completed = 1',
        [user_id, levelQuizIds]
      );

      // Agar 10 quizzes complete ho gaye hain, to level up kar rahe hain
      if (completedCount[0].count >= Math.min(levelQuizIds.length, 10)) {
        currentLevel += 1;
        await connection.query('UPDATE users SET current_level = ? WHERE user_id = ?', [currentLevel, user_id]);
      }
    }

    // User ka progress fetch kar rahe hain
    const [progressRows] = await connection.query(
      'SELECT quiz_id, attempts, completed FROM user_quiz_progress WHERE user_id = ?',
      [user_id]
    );
    const progressMap = new Map(progressRows.map(p => [p.quiz_id, p])); // Progress ko map mein store kar rahe hain

    const availableQuizzes = [];
    let canAccess = true;

    // Filtered quizzes ko sort kar rahe hain jo user ke level tak available hain
    const filteredQuizzes = quizzes
      .filter(q => q.level <= currentLevel)
      .sort((a, b) => a.quiz_id - b.quiz_id);

    for (const quiz of filteredQuizzes) {
      const progress = progressMap.get(quiz.quiz_id);
      const attempts = progress ? progress.attempts : 0;
      const completed = progress ? progress.completed : 0;

      // Agar quiz complete ho chuka hai to skip kar rahe hain
      if (completed) {
        canAccess = true;
        continue;
      }

      // Agar user ko access dena hai to quiz ko add kar rahe hain
      if (canAccess) {
        availableQuizzes.push({ ...quiz, attempts });
      }

      canAccess = progress && (progress.attempts > 0 || progress.completed);
    }

    await connection.commit(); // Commit kar rahe hain transaction ko
    res.json(availableQuizzes); // Available quizzes ko response mein bhej rahe hain
  } catch (error) {
    if (connection) await connection.rollback(); // Error aane par rollback kar rahe hain
    console.error('Error fetching quizzes:', error);
    res.status(500).json({ error: 'Server error' });
  } finally {
    if (connection) connection.release(); // Connection ko release kar rahe hain
  }
});

// Endpoint to get questions of a specific quiz
router.get('/quizzes/:quizId/questions', async (req, res) => {
  const { quizId } = req.params;
  if (!quizId || isNaN(parseInt(quizId))) {
    return res.status(400).json({ error: 'Invalid quiz ID' });
  }
  const quizIdNum = parseInt(quizId);

  try {
    const quiz = quizzes.find(q => q.quiz_id === quizIdNum);
    if (!quiz) return res.status(404).json({ error: 'Quiz not found' });

    // Questions ko fetch kar rahe hain aur response mein bhej rahe hain
    const questions = quiz.questions.map(q => ({
      question_id: q.question_id,
      question_text: q.question_text,
      option_a: q.option_a,
      option_b: q.option_b,
      option_c: q.option_c,
      option_d: q.option_d,
    }));

    res.json(questions); // Questions ko response mein bhej rahe hain
  } catch (error) {
    console.error('Error fetching questions:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Endpoint to submit quiz answers and calculate score
router.post('/quizzes/:quizId/submit', async (req, res) => {
  const { user_id, answers } = req.body; // User ID aur answers ko body se le rahe hain
  const { quizId } = req.params;

  if (!quizId || isNaN(parseInt(quizId))) {
    return res.status(400).json({ error: 'Invalid quiz ID' });
  }
  if (!user_id || !answers || !Array.isArray(answers)) {
    return res.status(400).json({ error: 'Invalid request' });
  }
  const quizIdNum = parseInt(quizId);

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();

    const quiz = quizzes.find(q => q.quiz_id === quizIdNum);
    if (!quiz) throw new Error('Quiz not found');

    // User ke progress ko fetch kar rahe hain
    const [progressRows] = await connection.query(
      'SELECT attempts, completed, reward_earned FROM user_quiz_progress WHERE user_id = ? AND quiz_id = ?',
      [user_id, quizId]
    );
    const existingProgress = progressRows[0];
    const alreadyCompleted = existingProgress ? existingProgress.completed === 1 : false;
    const rewardEarned = existingProgress ? existingProgress.reward_earned || 0 : 0;
    const attempts = (existingProgress ? existingProgress.attempts : 0) + 1;

    let totalScore = 0;
    let totalDeduction = 0;
    const totalPoints = quiz.questions.reduce((sum, q) => sum + q.points, 0);
    const answerFeedback = [];  

    // Existing answers ko delete kar rahe hain
    await connection.query(
      'DELETE FROM user_question_answers WHERE progress_id IN (SELECT progress_id FROM user_quiz_progress WHERE user_id = ? AND quiz_id = ?)',
      [user_id, quizId]
    );

    // Agar user ka progress already hai to update kar rahe hain, otherwise new progress insert kar rahe hain
    if (existingProgress) {
      await connection.query(
        'UPDATE user_quiz_progress SET attempts = ? WHERE user_id = ? AND quiz_id = ?',
        [attempts, user_id, quizId]
      );
    } else {
      await connection.query(
        'INSERT INTO user_quiz_progress (user_id, quiz_id, attempts) VALUES (?, ?, ?)',
        [user_id, quizId, attempts]
      );
    }

    // User ke answers ko process kar rahe hain aur score calculate kar rahe hain
    const [progressResult] = await connection.query(
      'SELECT progress_id FROM user_quiz_progress WHERE user_id = ? AND quiz_id = ?',
      [user_id, quizId]
    );
    const progressId = progressResult[0].progress_id;

    const [user] = await connection.query('SELECT current_level FROM users WHERE user_id = ?', [user_id]);
    const currentLevel = user[0].current_level;

    for (const answer of answers) {
      const question = quiz.questions.find(q => q.question_id === answer.question_id);
      if (!question) throw new Error(`Invalid question ID: ${answer.question_id}`);
      const isCorrect = answer.user_answer === question.correct_answer;
      let pointsEarned = isCorrect ? question.points : 0;
      let deduction = 0;

      // Agar answer galat hai aur user ka level 5 ya usse zyada hai, to deduction kar rahe hain
      if (!isCorrect && currentLevel >= 5) {
        deduction = 50;
        totalDeduction += deduction;
        await connection.query(
          'UPDATE users SET wallet_balance = wallet_balance - ? WHERE user_id = ?',
          [deduction, user_id]
        );
      }

      // User ke answers ko database mein insert kar rahe hain
      await connection.query(
        'INSERT INTO user_question_answers (progress_id, question_id, user_answer, is_correct, points_earned) VALUES (?, ?, ?, ?, ?)',
        [progressId, answer.question_id, answer.user_answer, isCorrect, pointsEarned]
      );
      totalScore += pointsEarned;

      answerFeedback.push({
        question_id: answer.question_id,
        user_answer: answer.user_answer,
        is_correct: isCorrect,
        correct_answer: question.correct_answer,
        deduction: deduction,
      });
    }

    const completed = answerFeedback.every(feedback => feedback.is_correct);
    let newRewardEarned = rewardEarned;

    // Agar quiz complete ho gaya hai to reward update kar rahe hain
    if (completed && !alreadyCompleted) {
      newRewardEarned = quiz.reward_points;
      await connection.query(
        'UPDATE users SET wallet_balance = wallet_balance + ? WHERE user_id = ?',
        [newRewardEarned, user_id]
      );
    }

    // Quiz progress ko update kar rahe hain
    await connection.query(
      'UPDATE user_quiz_progress SET score = ?, completed = ?, reward_earned = ? WHERE progress_id = ?',
      [totalScore, completed ? 1 : 0, newRewardEarned, progressId]
    );

    // Level up check kar rahe hain
    const levelQuizIds = quizzes.filter(q => q.level === currentLevel).map(q => q.quiz_id);
    const [completedCount] = await connection.query(
      'SELECT COUNT(DISTINCT quiz_id) AS count FROM user_quiz_progress WHERE user_id = ? AND quiz_id IN (?) AND completed = 1',
      [user_id, levelQuizIds]
    );
    let levelUp = false;
    let newLevel = currentLevel;

    if (levelQuizIds.length > 0 && completedCount[0].count >= Math.min(levelQuizIds.length, 10)) {
      newLevel = currentLevel + 1;
      await connection.query('UPDATE users SET current_level = ? WHERE user_id = ?', [newLevel, user_id]);
      levelUp = true;
    }

    await connection.commit(); // Commit kar rahe hain transaction ko

    res.json({
      score: totalScore,
      total_points: totalPoints,
      reward_earned: newRewardEarned,
      total_deduction: totalDeduction,
      completed,
      level_up: levelUp,
      new_level: newLevel,
      attempts,
      answer_feedback: answerFeedback,
    });
  } catch (error) {
    if (connection) await connection.rollback(); // Error ke case mein rollback
    console.error('Error submitting quiz:', error);
    res.status(400).json({ error: error.message || 'Server error' });
  } finally {
    if (connection) connection.release(); // Connection release kar rahe hain
  }
});

module.exports = router; // Router ko export kar rahe hain
