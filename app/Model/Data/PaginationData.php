<?php

namespace App\Model\Data;

use Swoft\Db\DB;
use Swoft\Db\Query\Builder;

/**
 * 分页类
 * Class PaginationData
 * @package App\Model\Data
 */
class PaginationData
{

    /**
     * @var Builder
     */
    private static $db_obj;
    private static $count = 0;

    private $page_num = 10;
    private $cur_page = 1;

    /**
     * @param string $table
     * @return static
     * @throws \Swoft\Db\Exception\DbException
     */
    public static function table(string $table): self
    {
        self::$db_obj = DB::table($table);
        self::$count = self::$db_obj->count();
        return new self();
    }

    /**
     * @param string ...$columns
     * @return $this
     */
    public function select(string ...$columns): self
    {
        self::$db_obj->select(...$columns);
        return $this;
    }

    /**
     * @param $column
     * @param null $operator
     * @param null $value
     * @param string $boolean
     * @return $this
     * @throws \Swoft\Db\Exception\DbException
     */
    public function where($column, $operator = null, $value = null, string $boolean = 'and')
    {
        self::$db_obj->where($column, $operator, $value, $boolean);
        self::$count = self::$db_obj->count();
        return $this;
    }

    /**
     * @param $column
     * @param $values
     * @param string $boolean
     * @param bool $not
     * @return $this
     * @throws \Swoft\Db\Exception\DbException
     */
    public function whereIn($column, $values, $boolean = 'and', $not = false)
    {
        self::$db_obj->whereIn($column, $values, $boolean, $not);
        self::$count = self::$db_obj->count();
        return $this;
    }

    /**
     * @param string $column
     * @param array  $data
     * @return $this
     * @throws \Swoft\Db\Exception\DbException
     */
    public function whereBetween($column, $data)
    {
        self::$db_obj->whereBetween($column, $data);
        self::$count = self::$db_obj->count();
        return $this;
    }

    /**
     * @param $page
     * @param $page_num
     * @return PaginationData
     */
    public function forPage($page, $page_num)
    {
        self::$db_obj->forPage($page, $page_num);
        $this->page_num = $page_num;
        $this->cur_page = $page;
        return $this;
    }

    /**
     * @param string $column
     * @param string $direction
     * @return $this
     */
    public function orderBy(string $column, string $direction = 'asc')
    {
        self::$db_obj->orderBy($column, $direction);
        return $this;
    }

    /**
     * @param string $column
     * @return PaginationData
     */
    public function orderByDesc(string $column)
    {
        self::$db_obj->orderByDesc($column);
        return $this;
    }

    /**
     * @param string $table
     * @param $first
     * @param string|null $operator
     * @param string|null $second
     * @return $this
     */
    public function leftJoin(string $table, $first, string $operator = null, string $second = null): self
    {
        self::$db_obj->leftJoin($table, $first, $operator, $second);
        return $this;
    }

    /**
     * @param string $table
     * @param $first
     * @param string|null $operator
     * @param string|null $second
     * @return $this
     */
    public function rightJoin(string $table, $first, string $operator = null, string $second = null): self
    {
        self::$db_obj->rightJoin($table, $first, $operator, $second);
        return $this;
    }

    /**
     * @return array
     */
    public function get()
    {
        return [
            'data' => self::$db_obj->get()->toArray(),
            'count' => self::$count,
            'cur_page' => $this->cur_page,
            'total_page' => ceil(self::$count / $this->page_num)
        ];
    }

    /**
     * @return int
     */
    public function count()
    {
        return self::$db_obj->count();
    }


}
